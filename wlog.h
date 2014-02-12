#ifndef WLOG_H_
#define WLOG_H_
#ifdef __linux__
#include <pwd.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#define gettid() syscall(__NR_gettid)
#define PATH_SPERATE '/'
#elif defined(WIN32)
#include <direct.h>
#include <io.h>
#include <windows.h>
#define PATH_SPERATE '\\'
#define gettid() GetCurrentThreadId()
#define mkdir(x,y)	_mkdir(x)
#endif

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include "g_var.h"

using std::string;

#define LOG_MUCH	__LINE__,__FILE__,__FUNCTION__
#define LOG_DEBUG	0,LOG_MUCH
#define LOG_INFO	1,LOG_MUCH
#define LOG_WARNING	2,LOG_MUCH
#define LOG_ERROR	3,LOG_MUCH

#define LOG_MAX_SIZE	10	//10M
#define LOG_NUM_KEEP	10
#define endl 		LogHelper(__LINE__,__FILE__,__FUNCTION__)

#ifdef WIN32
inline static int gettimeofday(struct timeval *tv, void* tz)
{
#define EPOCHFILETIME (116444736000000000ULL)
  FILETIME ft;
  LARGE_INTEGER li;
  unsigned long long tt;

  GetSystemTimeAsFileTime(&ft);
  li.LowPart = ft.dwLowDateTime;
  li.HighPart = ft.dwHighDateTime;
  tt = (li.QuadPart - EPOCHFILETIME) / 10;
  tv->tv_sec = time((time_t*)&(tv->tv_sec));//tt / 1000000;
  tv->tv_usec = tt % 1000000;

  return 0;
}

#define localtime_r(x,y)	localtime_s(y,x)
#define snprintf	sprintf_s
#endif


class WLock
{
public:
	WLock()
	{
#ifdef __linux
		//设置锁的互斥类型，为了支持在一个线程内部多次调用lock操作而不阻塞
		//缺省为PTHREAD_MUTEX_NORMAL ,我们把其设置为PTHREAD_MUTEX_RECURSIVE
		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
		pthread_mutex_init(&m_mutex,&attr);
		pthread_mutexattr_destroy (&attr);
#elif defined(WIN32)
		::InitializeCriticalSection( &m_CriticalSection );
#endif
	}

	~WLock()
	{
#ifdef __linux__
		pthread_mutex_destroy( &m_mutex );
#elif defined(WIN32)
		::DeleteCriticalSection( &m_CriticalSection );
#endif
	}

	void Lock()
	{
#ifdef __linux__
		pthread_mutex_lock( &m_mutex );
#elif defined(WIN32)
		::EnterCriticalSection( &m_CriticalSection );
#endif
	}

	void Unlock()
	{
#ifdef __linux
		pthread_mutex_unlock( &m_mutex );
#elif defined(WIN32)
		::LeaveCriticalSection( &m_CriticalSection );
#endif
	}

private:
#ifdef __linux
	pthread_mutex_t  m_mutex;
#elif defined(WIN32)
	CRITICAL_SECTION m_CriticalSection;
#endif
};

class LogHelper
{
public:
	LogHelper(int line, const char *file, const char *function)
	{
		m_line = line;
		strcpy(m_file,file);
		strcpy(m_function,function);
	}
public:
	int m_line;
	char m_file[1024];
	char m_function[256];
};


class ULog
{
public:
	//日志输出方式，1：写文件，2：屏幕，3都有
	ULog(const char* logfile, int logLevel = 1, int maxsize = LOG_MAX_SIZE, const char *maindir = logDir)
	{
		logtype = logType;
		level = logLevel;

		if(logtype & 0x01 == 0)
		{
			length = 0;
			capacity = INT_MAX;
			return;
		}

		mkdir(maindir,0777);
		if(maxsize <= 0)
			maxsize = 1;
		capacity = maxsize*1024*1024;

		SetCreateMessage();

		if(logfile == NULL || logfile[0] == 0)
			strcpy(fileName,GetModuleFileName().c_str());
		else
			strcpy(fileName,logfile);
		strcat(fileName,".log");

		if(maindir == NULL || maindir[0] == 0)
			strcpy(filePath,"");
		else
			strncpy(filePath,maindir,sizeof(filePath));

		if(strlen(filePath) > 0 && filePath[strlen(filePath)-1] != PATH_SPERATE)
		{
			char p[2] = {PATH_SPERATE,0};
			strcat(filePath,p);
		}
		strcat(filePath,fileName);

		m_file = fopen(filePath,"a");
		if(m_file == NULL)
		{
			printf("can't open %s",filePath);
			exit(-1);
		}

		struct stat buf;
		if(stat(filePath,&buf) == 0)
		{
			length = buf.st_size;
		}
		else
		{
			printf("can't open %s",filePath);
			exit(-1);
		}

		if(length > capacity)
			ChangeFile();
		LogWrite(createMessage);
	}

	~ULog()
	{
		fclose(m_file);
	}

	void Log(int logLevel, int line, const char *file, const char *function, const char *message,...)
	{
		if(logLevel < level || logtype == 0)
			return;
		va_list ap;
		va_start(ap,message);
		char sprint_buf[1024] = {0};
		vsnprintf(sprint_buf, sizeof(sprint_buf)-1, message, ap);
		va_end(ap);

		struct timeval tv;
		gettimeofday(&tv, NULL);
		struct tm curt;
		time_t time = tv.tv_sec;
		localtime_r(&time,&curt);
		char *fileName;
		char pfile[256];
		strncpy(pfile, file, sizeof(pfile));
		if((fileName = strrchr(pfile,PATH_SPERATE)) != NULL)
			fileName++;
		else
			fileName = pfile;

		const char logLevelStr[][16] = {"Debug","Info","Warning","Error","Fatal"};
		char printf_buf[1024];
		int len = snprintf(printf_buf, sizeof(printf_buf)-1, "%02d-%02d %02d:%02d:%02d.%06ld][%s][%s-%d][%ld]%s",
				curt.tm_mon+1,curt.tm_mday,curt.tm_hour,curt.tm_min,curt.tm_sec,tv.tv_usec,
				logLevelStr[logLevel], function, line, gettid(),sprint_buf);
		if(printf_buf[len - 1] != '\n')
		{
			printf_buf[len++] = '\n';
			printf_buf[len] = '\0';
		}

		if(logtype & 0x01)
			LogWrite(printf_buf);
		if(logtype & 0x02)
			printf(printf_buf);
	}

	ULog& operator<<(const char *str)
	{
		logBuffer += str;
		return *this;
	}

	ULog& operator<<(const LogHelper &flush)
	{
		Log(3,flush.m_line,flush.m_file,flush.m_function,logBuffer.c_str());
		logBuffer.clear();
		return *this;
	}

private:
	void ChangeFile()
	{
		fclose(m_file);
		int keep = LOG_NUM_KEEP;
		char newfile[1024],oldfile[1024];

		while(--keep)
		{
			snprintf(oldfile,sizeof(oldfile),"%s.%d",filePath,keep);
			snprintf(newfile,sizeof(newfile),"%s.%d",filePath,keep + 1);
			if(access(oldfile,0) == 0)
			{
				rename(oldfile,newfile);
			}
		}
		snprintf(newfile,sizeof(newfile),"%s.1",filePath);
		if(access(filePath,0) == 0)
		{
			rename(filePath,newfile);
		}
		m_file = fopen(filePath,"w+");
		if(m_file == NULL)
		{
			printf("can't open %s",filePath);
			exit(-1);
		}
		length = 0;
	}

	int LogWrite(const char *logStr)
	{
		m_lock.Lock();
		unsigned int len = strlen(logStr);
		length += len;
		if(length > capacity)
		{
			ChangeFile();//length has changed
			length += len;
		}
		if(m_file == NULL)
		{
			printf("err");
		}
		if(fwrite(logStr,1,len,m_file) != len)
		{
			printf("Error, can't write log!!!");
		}
//#ifdef DEBUG
		fflush(m_file);
//#endif
		m_lock.Unlock();
		return 0;
	}

	void SetCreateMessage()
	{
		time_t tm = time(&tm);
		struct tm date;
		localtime_r(&tm,&date);
		sprintf(createMessage,"=============================================================\n"
							  "\tCreate in %04d-%02d-%02d %02d:%02d:%02d by %s(%s)\n"
							   "=============================================================\n",
				date.tm_year + 1900, date.tm_mon + 1, date.tm_mday,date.tm_hour,date.tm_min,date.tm_sec,
				GetModuleFileName().c_str(), GetCurrentUser().c_str());
	}

private:

	string GetModuleFileName()
	{
#ifdef __linux__
		char path[128];
		sprintf(path,"/proc/%d/exe",getpid());

		char moduleFileName[1024];
		int readsize = readlink(path, moduleFileName, sizeof(moduleFileName));
		if (readsize == -1) {
			return NULL;
		}
		else
		{
			moduleFileName[readsize] = '\0';
			char *p;
			if((p = strrchr(moduleFileName,'/')) != NULL)
			{
				return p + 1;
			}
			else
				return moduleFileName;
		}
#elif defined(WIN32)
		TCHAR szPath[MAX_PATH];
		::GetModuleFileName(NULL,szPath,MAX_PATH);
		char pBuf[MAX_PATH];
		::WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,szPath,wcslen(szPath)+1,pBuf,MAX_PATH,NULL,NULL);
		char *p = strrchr(pBuf,'\\');
		if(p)
			return p+1;
		else
			return (char*)pBuf;
#endif
	}

	string GetCurrentUser()
	{
#ifdef __linux__
		struct passwd *pwd;
		pwd = getpwuid(getuid());
		return pwd->pw_name;
#elif defined(WIN32)
		TCHAR szPath[MAX_PATH];
		DWORD size=MAX_PATH;
		::GetUserName(szPath,(LPDWORD)&size);
		char pBuf[MAX_PATH];
		::WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,szPath,wcslen(szPath)+1,pBuf,MAX_PATH,NULL,NULL);
		return (char*)pBuf;
#endif
	}


private:
	string logBuffer;
	int level;
	int logtype;
	WLock m_lock;
	FILE *m_file;
	long long length;
	long long capacity;
	char filePath[1024];
	char fileName[256];
	char createMessage[1024];
};

inline void logToDefault(int logLevel, int line, const char *file, const char *fun, const char *message,...)
{
	static WLock lock;
	lock.Lock();
	static ULog defaultLog("default",0);
	lock.Unlock();
	char sprint_buf[1024] = {0};
	va_list ap;
	va_start(ap,message);
	vsnprintf(sprint_buf, sizeof(sprint_buf), message, ap);
	va_end(ap);

	defaultLog.Log(logLevel, line, file, fun, sprint_buf);
}
inline void logToUserSession(int logLevel, int line, const char *file, const char *fun, const char *message,...)
{
	static WLock lock;
	lock.Lock();
	static ULog defaultLog("usersession",0);
	lock.Unlock();
	char sprint_buf[1024] = {0};
	va_list ap;
	va_start(ap,message);
	vsnprintf(sprint_buf, sizeof(sprint_buf), message, ap);
	va_end(ap);

	defaultLog.Log(logLevel, line, file, fun, sprint_buf);
}
inline void logToTSipTServerDefault(int logLevel, int line, const char *file, const char *fun, const char *message,...)
{
	static WLock lock;
	lock.Lock();
	static ULog defaultLog("tsiptserver",0);
	lock.Unlock();
	char sprint_buf[1024] = {0};
	va_list ap;
	va_start(ap,message);
	vsnprintf(sprint_buf, sizeof(sprint_buf), message, ap);
	va_end(ap);

	defaultLog.Log(logLevel, line, file, fun, sprint_buf);
}


inline void logToTSipTransationDefault(int logLevel, int line, const char *file, const char *fun, const char *message,...)
{
	static WLock lock;
	lock.Lock();
	static ULog defaultLog("tsiptransation",0);
	lock.Unlock();
	char sprint_buf[1024] = {0};
	va_list ap;
	va_start(ap,message);
	vsnprintf(sprint_buf, sizeof(sprint_buf), message, ap);
	va_end(ap);

	defaultLog.Log(logLevel, line, file, fun, sprint_buf);
}
#endif /* WLOG_H_ */
