#include "logger.h"

#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <pthread.h>

#include <ctime>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <deque>
#include <string>

/************************************************************************
* PRIVATE DEFINITIONS
************************************************************************/

#define LOG_LINE_MAX		2048
#define LOG_BUFF_SIZE		1024 * 1024
#define LOG_MAX_PATH_SIZE	256

#define STRERROR(no) (strerror(no) != NULL ? strerror(no) : "Unkown error")

/* 日志切分周期枚举 */
typedef enum {
	ROTATE_CYCLE_NONE = 0,
	ROTATE_CYCLE_MINUTE = 1, 
	ROTATE_CYCLE_HOUR = 2,
	ROTATE_CYCLE_DAY = 3
} LOGROTATE_CYCLE;

/* 专用于写磁盘的线程上下文 */
typedef struct disk_thread_context {
	/* 写磁盘线程id */
	pthread_t disk_pthread_id;

	/* 写磁盘操作请求队列 */
	std::deque<std::string> *blocking_queue;

	/* 多线程mutex */
	pthread_mutex_t disk_thread_lock; 

	/* 多线程condition */
	pthread_cond_t disk_thread_cond;

	/* 通知磁盘线程退出 */
	bool disk_thread_stop;
} DISK_THREAD_CONTEXT;

/* 供模块内部使用的日志上下文结构 */
typedef struct log_context {
	/* 日志级别, 可参考<sys/syslog.h>. 默认级别是LOG_INFO */
	int log_level;

	/* 日志文件fd, 默认值是 STDERR_FILENO */
	int log_fd;

	/* 日志切分时间周期, 默认为天 */
	LOGROTATE_CYCLE logrotate_cycle;

	/* 日志文件根目录, 默认值是空 */
	char *log_base_path;

	/* 日志文件名前缀, 默认值是空 */
	char *log_filename_prefix;

	/* 日志buffer */
	char *log_buff;

	/* 指向当前缓冲区可用区域的首地址 */
	char *pcurrent_buff;

	/* 多线程mutex */
	pthread_mutex_t log_thread_lock; 

	/* 是否先写到缓冲, 再从缓冲写入磁盘. 默认不采用缓冲 */
	bool log_to_cache;

	/* 专用于写磁盘线程上下文 */
	DISK_THREAD_CONTEXT disk_thread_ctx;	
} LogContext;

/************************************************************************
* PRIVATE VARIABLES
************************************************************************/

/*  日志模块全局上下文, 在log_init中初始化 */
LogContext *pContext = NULL;

/* 记录上次写日志的时间, 主要用于日志切分 */
static int last_log_time = 0;

/* 记录模块是否已经成功初始化 */
static int logger_init_flag = 0;

/* 主线程和磁盘线程初始化和停止操作同步设施 */
static pthread_mutex_t thread_init_lock;
static pthread_cond_t thread_init_cond;
static int thread_init_flag = 0;

/************************************************************************
* PRIVATE FUNCTION PROTOTYPES
************************************************************************/

static void* disk_write_thread(void*);
static int log_fsync(const bool bNeedLock);
static int check_and_mk_log_dir(const char *base_path);

/************************************************************************
* IMPLEMENTATION OF PUBLIC FUNCTIONS
************************************************************************/

int log_init()
{
	time_t t;
	struct tm tm;
	int result = 0;
	int log_thread_lock_init = 0, disk_thread_lock_init = 0, disk_thread_cond_init = 0;

	pthread_mutexattr_t mtxAttr;
	pthread_t disk_pthread_id;
	pthread_attr_t thread_attr;

	if (logger_init_flag) {
		fprintf(stderr, "logger module has already been init!!\n");
		return 1;
	}

	do {
		pContext = (LogContext *)malloc(sizeof(LogContext));

		if (pContext == NULL) {
			fprintf(stderr, "malloc %lu bytes fail, errno: %d, error info: %s", sizeof(LogContext), errno, STRERROR(errno));
			return (errno != 0) ? errno : ENOMEM;
		}

		pContext->log_level = LOG_INFO;
		pContext->log_fd = STDERR_FILENO;
		pContext->log_base_path = NULL;
		pContext->log_filename_prefix = NULL;
		pContext->log_to_cache = false;
		pContext->logrotate_cycle = ROTATE_CYCLE_DAY;

		/* 初始化日志buff */
		pContext->log_buff = (char *)malloc(LOG_BUFF_SIZE);

		if (pContext->log_buff == NULL) {
			fprintf(stderr, "malloc %d bytes fail, errno: %d, error info: %s", LOG_BUFF_SIZE, errno, STRERROR(errno));
			result = (errno != 0) ? errno : ENOMEM;
			break;
		}

		pContext->pcurrent_buff = pContext->log_buff;

		/* 设置锁为纠错锁, 同一线程不能重复加锁, 加上的锁只能由本线程解锁. 先等待锁的线程先获得锁 */
		pthread_mutexattr_init(&mtxAttr);
		pthread_mutexattr_settype(&mtxAttr, PTHREAD_MUTEX_ERRORCHECK_NP);

		if ((result = pthread_mutex_init(&(pContext->log_thread_lock), &mtxAttr)) != 0) {
			fprintf(stderr, "call pthread_mutex_init fail, errno: %d, error info: %s", result, STRERROR(result));
			break;
		}

		pthread_mutexattr_destroy(&mtxAttr);
		log_thread_lock_init = 1;

		/* 初始化写磁盘线程上下文 */
		if ((result = pthread_mutex_init(&(pContext->disk_thread_ctx.disk_thread_lock), NULL)) != 0) {
			fprintf(stderr, "call pthread_mutex_init fail, errno: %d, error info: %s", result, STRERROR(result));
			break;
		}

		disk_thread_lock_init = 1;

		if ((result = pthread_cond_init(&(pContext->disk_thread_ctx.disk_thread_cond), NULL)) != 0) {
			fprintf(stderr, "call pthread_cond_init fail, errno: %d, error info: %s", result, STRERROR(result));
			break;
		}

		disk_thread_cond_init = 1;

		pContext->disk_thread_ctx.disk_thread_stop = false;
		pContext->disk_thread_ctx.blocking_queue = new std::deque<std::string>;

		/* 启动磁盘线程 */
		pthread_attr_init(&thread_attr);
		pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

		if ((result = pthread_create(&disk_pthread_id, &thread_attr, disk_write_thread, NULL)) != 0) {
			fprintf(stderr, "call pthread_create fail, errno: %d, error info: %s", result, STRERROR(result));
			break;
		}

		pContext->disk_thread_ctx.disk_pthread_id = disk_pthread_id;
		pthread_attr_destroy(&thread_attr);

		/* 等待磁盘线程运行成功 */
		pthread_mutex_init(&thread_init_lock, NULL);
		pthread_cond_init(&thread_init_cond, NULL);

		pthread_mutex_lock(&thread_init_lock);
		while (!thread_init_flag) {
			pthread_cond_wait(&thread_init_cond, &thread_init_lock);	
		}
		pthread_mutex_unlock(&thread_init_lock);

		/* 记录当前时间 */
		t = time(NULL);
		localtime_r(&t, &tm);

		switch (pContext->logrotate_cycle) {
		case ROTATE_CYCLE_NONE:
			last_log_time = -1;
			break;

		case ROTATE_CYCLE_MINUTE:
			last_log_time = tm.tm_min;
			break;

		case ROTATE_CYCLE_HOUR:
			last_log_time = tm.tm_hour;
			break;

		case ROTATE_CYCLE_DAY:
			last_log_time = tm.tm_yday;
			break;
		}

		/* 模块初始化成功 */
		logger_init_flag = 1; 
		return 0;

	} while (0);

	/* 出现错误, 回收资源 */
	if (log_thread_lock_init) {
		pthread_mutex_destroy(&pContext->log_thread_lock);
	}

	if (disk_thread_lock_init) {
		pthread_mutex_destroy(&pContext->disk_thread_ctx.disk_thread_lock);
	}

	if (disk_thread_cond_init) {
		pthread_cond_destroy(&pContext->disk_thread_ctx.disk_thread_cond);
	}

	if (pContext->log_buff) {
		free(pContext->log_buff);
	}
	
	if (pContext) {
		free(pContext);
		pContext = NULL;
	}

	return result;
}

void log_destroy()
{
	if (!logger_init_flag) {
		return;
	}

	/* 将模块标记为无效, 并等待其他用户线程完成操作 */
	logger_init_flag = 0;
	pthread_mutex_lock(&pContext->log_thread_lock);

	/* 停止写磁盘线程 */
	pContext->disk_thread_ctx.disk_thread_stop = true;
	pthread_cond_signal(&pContext->disk_thread_ctx.disk_thread_cond);

	/* 等待磁盘线程停止成功 */
	pthread_mutex_lock(&thread_init_lock);
	while (thread_init_flag) {
		pthread_cond_wait(&thread_init_cond, &thread_init_lock);	
	}
	pthread_mutex_unlock(&thread_init_lock);

	if (pContext->log_fd >= 0) {
		/* 模块退出前, 将缓冲区和队列中的log写到磁盘上 */
		if (pContext->pcurrent_buff - pContext->log_buff) {
			pContext->disk_thread_ctx.blocking_queue->push_back(std::string(pContext->log_buff, pContext->pcurrent_buff));
			pContext->pcurrent_buff = pContext->log_buff;
		}

		while (!pContext->disk_thread_ctx.blocking_queue->empty()) {
			std::string log_msg = pContext->disk_thread_ctx.blocking_queue->front();
			pContext->disk_thread_ctx.blocking_queue->pop_front();
			write(pContext->log_fd, log_msg.c_str(), log_msg.size());
		}

		if (pContext->log_fd != STDERR_FILENO) {
			close(pContext->log_fd);
			pContext->log_fd = STDERR_FILENO;
		}
	}

	delete pContext->disk_thread_ctx.blocking_queue;
	pthread_mutex_destroy(&pContext->disk_thread_ctx.disk_thread_lock);
	pthread_cond_destroy(&pContext->disk_thread_ctx.disk_thread_cond);

	if (pContext->log_base_path) {
		free(pContext->log_base_path);
		pContext->log_base_path = NULL;
	}

	if (pContext->log_filename_prefix) {
		free(pContext->log_filename_prefix);	
		pContext->log_filename_prefix = NULL;
	}

	if (pContext->log_buff != NULL) {
		free(pContext->log_buff);
		pContext->log_buff = NULL;
		pContext->pcurrent_buff = NULL;
	}

	pthread_mutex_unlock(&pContext->log_thread_lock);
	pthread_mutex_destroy(&pContext->log_thread_lock);

	free(pContext);
	pContext = NULL;
}

int log_set_level(const char *pLogLevel)
{
	if (!logger_init_flag) {
		fprintf(stderr, "log module may be not init!\n");
		return 1;	
	}

	if (!pLogLevel) {
		fprintf(stderr, "log level can not be empty\n");
		return 1;
	}

	if (strncasecmp(pLogLevel, "DEBUG", 5) == 0 || strcmp(pLogLevel, "LOG_DEBUG") == 0) {
		pContext->log_level = LOG_DEBUG;
	} else if (strncasecmp(pLogLevel, "INFO", 4) == 0 || strcmp(pLogLevel, "LOG_INFO") == 0) {
		pContext->log_level = LOG_INFO;
	} else if (strncasecmp(pLogLevel, "NOTICE", 6) == 0 || strcmp(pLogLevel, "LOG_NOTICE") == 0) {
		pContext->log_level = LOG_NOTICE;
	} else if (strncasecmp(pLogLevel, "WARN", 4) == 0 || strcmp(pLogLevel, "LOG_WARNING") == 0) {
		pContext->log_level = LOG_WARNING;
	} else if (strncasecmp(pLogLevel, "ERR", 3) == 0 || strcmp(pLogLevel, "LOG_ERR") == 0) {
		pContext->log_level = LOG_ERR;
	} else if (strncasecmp(pLogLevel, "CRIT", 4) == 0 || strcmp(pLogLevel, "LOG_CRIT") == 0) {
		pContext->log_level = LOG_CRIT;
	} else if (strncasecmp(pLogLevel, "ALERT", 5) == 0 || strcmp(pLogLevel, "LOG_ALERT") == 0) {
		pContext->log_level = LOG_ALERT;
	} else if (strncasecmp(pLogLevel, "EMERG", 5) == 0 || strcmp(pLogLevel, "LOG_EMERG") == 0) {
		pContext->log_level = LOG_EMERG;
	} else {
		fprintf(stderr, "invalid log level \"%s\"\n", pLogLevel);
		return 1;	
	}

	return 0;
}

int log_set_prefix(const char *base_path, const char *filename_prefix)
{
	int result;
	char logfile[LOG_MAX_PATH_SIZE];

	if (!logger_init_flag) {
		fprintf(stderr, "log module may be not init!\n");
		return 1;	
	}
	
	if (!base_path || !filename_prefix) {
		fprintf(stderr, "base_path or filename_prefix can not be empty\n");
		return 1;	
	}

	if ((strlen(base_path) + strlen(filename_prefix) + sizeof("/log/.log") - 1) >= LOG_MAX_PATH_SIZE) {
		fprintf(stderr, "full file name of log file can not be longer than %d\n", LOG_MAX_PATH_SIZE);
		return 1;
	}

	if ((result = check_and_mk_log_dir(base_path)) != 0) {
		return result;
	}

	snprintf(logfile, LOG_MAX_PATH_SIZE, "%s/logs/%s.log", base_path, filename_prefix);

	if ((pContext->log_fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0644)) < 0) {
		fprintf(stderr, "open log file \"%s\" to write fail, errno: %d, error info: %s", logfile, errno, STRERROR(errno));
		pContext->log_fd = STDERR_FILENO;
		return (errno != 0) ? errno : EACCES;
	}

	if (!pContext->log_base_path) {
		pContext->log_base_path = (char *)malloc(LOG_MAX_PATH_SIZE);

		if (pContext->log_base_path == NULL) {
			fprintf(stderr, "malloc %d bytes fail, errno: %d, error info: %s", LOG_MAX_PATH_SIZE, errno, STRERROR(errno));
			return (errno != 0) ? errno : ENOMEM;
		}

		pContext->log_filename_prefix = (char *)malloc(LOG_MAX_PATH_SIZE);

		if (pContext->log_filename_prefix == NULL) {
			free(pContext->log_base_path);
			pContext->log_base_path = NULL;

			fprintf(stderr, "malloc %d bytes fail, errno: %d, error info: %s", LOG_MAX_PATH_SIZE, errno, STRERROR(errno));
			return (errno != 0) ? errno : ENOMEM;
		}
	}

	strcpy(pContext->log_base_path, base_path);
	strcpy(pContext->log_filename_prefix, filename_prefix);

	return 0;
}

int log_set_rotate_cycle(const char *pRotateCycle)
{
	time_t t;
	struct tm tm;
	int result = 0, retval = 0;

	if (!logger_init_flag) {
		fprintf(stderr, "log module may be not init!\n");
		return 1;
	}

	if (!pRotateCycle) {
		fprintf(stderr, "log rotate cycle can not be empty\n");
		return 1;
	}

	/* 加锁 */
	if ((result = pthread_mutex_lock(&pContext->log_thread_lock)) != 0) {
		fprintf(stderr, "file: " __FILE__ ", line: %d, call pthread_mutex_lock fail, errno: %d, error info: %s", __LINE__, result, STRERROR(result));
	}

	t = time(NULL);
	localtime_r(&t, &tm);

	if (strcasecmp(pRotateCycle, "D") == 0) {
		pContext->logrotate_cycle = ROTATE_CYCLE_DAY;	
		last_log_time = tm.tm_yday;
	} else if (strcasecmp(pRotateCycle, "H") == 0) {
		pContext->logrotate_cycle = ROTATE_CYCLE_HOUR;
		last_log_time = tm.tm_hour;
	} else if (strcasecmp(pRotateCycle, "M") == 0) {
		pContext->logrotate_cycle = ROTATE_CYCLE_MINUTE;	
		last_log_time = tm.tm_min;
	} else if (strcasecmp(pRotateCycle, "NONE") == 0) {
		pContext->logrotate_cycle = ROTATE_CYCLE_NONE;
		last_log_time = -1;
	} else {
		fprintf(stderr, "invalid log rotate cycle \"%s\"\n", pRotateCycle);
		retval = 1;
	}

	/* 解锁 */
	if ((result = pthread_mutex_unlock(&(pContext->log_thread_lock))) != 0) {
		fprintf(stderr, "file: " __FILE__ ", line: %d, call pthread_mutex_unlock fail, errno: %d, error info: %s", __LINE__, result, STRERROR(result));
	}

	return retval;
}

int log_set_cache(const bool bLogCache)
{
	if (!logger_init_flag) {
		fprintf(stderr, "log module may be not init!\n");
		return 1;	
	}

	pContext->log_to_cache = bLogCache;
	return 0;
}

int log_force_sync()
{
	if (!logger_init_flag) {
		fprintf(stderr, "log module may be not init!\n");
		return 1;	
	}

	return log_fsync(true);
}

int logEx(int priority, const char *caption, const bool bNeedSync, 
		const char *file_name, const char *func_name, int line_number, const char *format, ...)
{
	char text[LOG_LINE_MAX];
	int text_len, log_fd;
	const char *p;

	struct timeval tv;
	long milliseconds;
	struct tm* tm;
	int buff_len;
	int result;

	if (!logger_init_flag) {
		fprintf(stderr, "log module may be not init!\n");
		return 1;
	}

	if (pContext->log_level < priority) {
		return 0;
	}

	va_list ap;
	va_start(ap, format);
	text_len = vsnprintf(text, sizeof(text), format, ap);
	va_end(ap);

	/* 日志太长, 无法打印到缓冲区 */
	if ((text_len + 128) > LOG_BUFF_SIZE) {
		fprintf(stderr, "file: " __FILE__ ", line: %d, log buff size: %d < log text length: %d ", __LINE__, LOG_BUFF_SIZE, text_len + 128);
		return 1;
	}

	/* 加锁 */
	if ((result = pthread_mutex_lock(&pContext->log_thread_lock)) != 0) {
		fprintf(stderr, "file: " __FILE__ ", line: %d, call pthread_mutex_lock fail, errno: %d, error info: %s", __LINE__, result, STRERROR(result));
	}

	/* 获取系统时间, 精确到毫秒 */
	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);
	milliseconds = tv.tv_usec / 1000;

	/* 缓冲区中剩余空间无法容纳本行日志, 先将缓冲区中日志写入磁盘文件 */
	if (((pContext->pcurrent_buff - pContext->log_buff) + text_len + 128) > LOG_BUFF_SIZE) {
		log_fsync(false);
	}

	/*  如果文件名存在路径前缀, 则去掉路径前缀 */
	if ((p = strrchr(file_name, '/')) != NULL) {
		p++;
	} else {
		p = file_name;
	}

	buff_len = sprintf(pContext->pcurrent_buff, "[%04d-%02d-%02d %02d:%02d:%02d:%03ld] [tid=%d] [%s::%s:%d] %s - ",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, milliseconds,
			(int)syscall(__NR_gettid), p, func_name, line_number, caption);

	pContext->pcurrent_buff += buff_len;
	memcpy(pContext->pcurrent_buff, text, text_len);
	pContext->pcurrent_buff += text_len;
	*pContext->pcurrent_buff++ = '\n';

	if (!pContext->log_to_cache || bNeedSync) {
		log_fsync(false);
	}

	/* 进行日志切分 */
	int cur_time = 0;

	switch (pContext->logrotate_cycle) {
	case ROTATE_CYCLE_NONE:
		cur_time = -1;
		break;

	case ROTATE_CYCLE_MINUTE:
		cur_time = tm->tm_min;
		break;

	case ROTATE_CYCLE_HOUR:
		cur_time = tm->tm_hour;
		break;

	case ROTATE_CYCLE_DAY:
		cur_time = tm->tm_yday;
		break;
	}

	if (cur_time != last_log_time && pContext->log_fd >= 0 && pContext->log_fd != STDERR_FILENO && pContext->logrotate_cycle != ROTATE_CYCLE_NONE) {
		/* 首先将缓冲中日志刷新到现在的日志文件中 */
		log_fsync(false);

		char cur_filename[LOG_MAX_PATH_SIZE];
		char log_filename[LOG_MAX_PATH_SIZE];
		char filename_time_suffix[16];

		switch (pContext->logrotate_cycle) {
		case ROTATE_CYCLE_NONE:
			/* just remove compile warnings */
			break;

		case ROTATE_CYCLE_MINUTE:
			snprintf(filename_time_suffix, sizeof(filename_time_suffix), "%04d%02d%02d-%02d%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, last_log_time);
			break;

		case ROTATE_CYCLE_HOUR:
			snprintf(filename_time_suffix, sizeof(filename_time_suffix), "%04d%02d%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, last_log_time);
			break;

		case ROTATE_CYCLE_DAY:
			snprintf(filename_time_suffix, sizeof(filename_time_suffix), "%04d%02d%02d", tm->tm_year + 1900, tm->tm_mon + 1, last_log_time);
			break;
		}

		snprintf(cur_filename, LOG_MAX_PATH_SIZE, "%s/logs/%s.log", pContext->log_base_path, pContext->log_filename_prefix);
		snprintf(log_filename, LOG_MAX_PATH_SIZE, "%s/logs/%s.%s.log", pContext->log_base_path, pContext->log_filename_prefix, filename_time_suffix);

		/* 将前一个时间段的日志切分出去 */
		if (rename(cur_filename, log_filename) < 0) {
			fprintf(stderr, "rename log file \"%s\" fail, errno: %d, error info: %s", cur_filename, errno, STRERROR(errno));
		} else {
			if ((log_fd = open(cur_filename, O_WRONLY | O_CREAT | O_APPEND, 0644)) < 0) {
				fprintf(stderr, "open log file \"%s\" to write fail, errno: %d, error info: %s", log_filename, errno, STRERROR(errno));
			} else {
				close(pContext->log_fd);
				pContext->log_fd = log_fd;
			}
		}
	}

	/* 更新最后一次日志时间 */
	last_log_time = cur_time;

	/* 解锁 */
	if ((result = pthread_mutex_unlock(&(pContext->log_thread_lock))) != 0) {
		fprintf(stderr, "file: " __FILE__ ", line: %d, call pthread_mutex_unlock fail, errno: %d, error info: %s", __LINE__, result, STRERROR(result));
	}

	return 0;
}

/************************************************************************
* PRIVATE FUNCTIONS IMPLEMENTATION
************************************************************************/

static int check_and_mk_log_dir(const char *base_path)
{
	char data_path[LOG_MAX_PATH_SIZE];
	snprintf(data_path, sizeof(data_path), "%s/logs", base_path);

	if (access(data_path, 0) != 0) {
		if (mkdir(data_path, 0755) != 0) {
			fprintf(stderr, "mkdir \"%s\" fail, errno: %d, error info: %s", data_path, errno, STRERROR(errno));
			return (errno != 0) ? errno : EPERM;
		}
	}

	return 0;
}

static void* disk_write_thread(void*)
{
	int result;
	int write_bytes;

	/* 完成磁盘线程初始化 */
	pthread_mutex_lock(&thread_init_lock);
	thread_init_flag = 1;
	pthread_cond_signal(&thread_init_cond);
	pthread_mutex_unlock(&thread_init_lock);

	/* 开始事件循环 */
	while (!pContext->disk_thread_ctx.disk_thread_stop) {
		pthread_mutex_lock(&pContext->disk_thread_ctx.disk_thread_lock);

		while (pContext->disk_thread_ctx.blocking_queue->empty() && !pContext->disk_thread_ctx.disk_thread_stop) {
			pthread_cond_wait(&(pContext->disk_thread_ctx.disk_thread_cond), &pContext->disk_thread_ctx.disk_thread_lock);	
		}

		if (!pContext->disk_thread_ctx.blocking_queue->empty()) {
			std::string log_msg = pContext->disk_thread_ctx.blocking_queue->front();
			pContext->disk_thread_ctx.blocking_queue->pop_front();
			pthread_mutex_unlock(&(pContext->disk_thread_ctx.disk_thread_lock));

			write_bytes = log_msg.size();
			if (write(pContext->log_fd, log_msg.c_str(), write_bytes) != write_bytes) {
				result = (errno != 0) ? errno : EIO;
				fprintf(stderr, "file: " __FILE__ ", line: %d, call write fail, errno: %d, error info: %s\n", __LINE__, result, STRERROR(result));
			}

			if (pContext->log_fd != STDERR_FILENO) {
				if (fsync(pContext->log_fd) != 0) {
					result = (errno != 0) ? errno : EIO;
					fprintf(stderr, "file: " __FILE__ ", line: %d, call fsync fail, errno: %d, error info: %s\n", __LINE__, result, STRERROR(result));
				}
			}
		} else {
			pthread_mutex_unlock(&(pContext->disk_thread_ctx.disk_thread_lock));
		}
	}

	/* 完成磁盘线程退出 */
	pthread_mutex_lock(&thread_init_lock);
	thread_init_flag = 0;
	pthread_cond_signal(&thread_init_cond);
	pthread_mutex_unlock(&thread_init_lock);

	return NULL;
}

static int log_fsync(const bool bNeedLock)
{
	int result = 0;

	if (bNeedLock && ((result = pthread_mutex_lock(&(pContext->log_thread_lock))) != 0)) {
		fprintf(stderr, "file: " __FILE__ ", line: %d, call pthread_mutex_lock fail, errno: %d, error info: %s", __LINE__, result, STRERROR(result));
	}

	pthread_mutex_lock(&pContext->disk_thread_ctx.disk_thread_lock);

	pContext->disk_thread_ctx.blocking_queue->push_back(std::string(pContext->log_buff, pContext->pcurrent_buff));
	pContext->pcurrent_buff = pContext->log_buff;

	pthread_cond_signal(&pContext->disk_thread_ctx.disk_thread_cond);
	pthread_mutex_unlock(&pContext->disk_thread_ctx.disk_thread_lock);

	if (bNeedLock && ((result = pthread_mutex_unlock(&(pContext->log_thread_lock))) != 0)) {
		fprintf(stderr, "file: " __FILE__ ", line: %d, call pthread_mutex_unlock fail, errno: %d, error info: %s", __LINE__, result, STRERROR(result));
	}

	return result;
}

