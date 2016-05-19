#include <stdio.h>
#include <pcre.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define OVECCOUNT 30    /* should be a multiple of 3 */

struct rules {
	char * name;
	char * quick_str;
	pcre * regex;
	struct rules *next;
} * ruletab=NULL;

void multiscan(char *path);

int scanfile(char* filepath) {
	FILE * f=fopen(filepath,"rt");
	char buf[65536];
	int len=-1;
	int ovector[OVECCOUNT];
	int rc;
	unsigned int line_num=0;
	struct rules *i;
	if (f==NULL) {
		printf("UNABLE TO OPEN %s\n",filepath);
		return 0;
	}
		
	while (!feof(f)) {
		if (fgets(buf,sizeof(buf),f)==NULL)
			break;
		line_num++;
		buf[65535]=0;
		len=-1;
		for (i=ruletab; i!=NULL; i=i->next) {
			//printf("testing %s on %s",i->name, buf);
			if (strstr(buf,i->quick_str)!=NULL) {
				//printf("rule %s, Found %s in '%s'\n",i->name, i->quick_str,buf);
				if (len==-1)
					len=strlen(buf);
				rc=pcre_exec(i->regex, NULL, buf, len, 0,0, ovector, OVECCOUNT);
				if (rc>=0)
					printf("RULE %s, REGEX MATCHED in '%s' +%d\n",i->name,filepath,line_num);
			}
		}
	}
	fclose(f);
	return 1;
}

int add_rule(char * name, char * quick, char * reg) {
	const char *error;
	int erroffset;
	struct rules *i,*t=(struct rules *) malloc(sizeof(struct rules));
	printf("Adding rule: '%s' '%s' '%s'\n",name,quick,reg);
	t->name=strdup(name);
	t->quick_str=strdup(quick);
	t->regex=pcre_compile(reg,0,&error, &erroffset,NULL);
	if (t->regex==NULL) {
		printf("RULE %s: PCRE failed at %d: %s\n",name, erroffset,error);
		return 0;
	}
	t->next=NULL;
	if (ruletab==NULL) {
		ruletab=t;
		return 1;
	}
	for (i=ruletab; i!=NULL; i=i->next)
		if (i->next==NULL) {
			i->next=t;
			break;
		}
	return 1;
}

void scan_dir(char *path) {
	char pathbuffer[65536];
	DIR *dp;
	struct dirent *entry;
	//printf("scanning %s\n",path);
	
	if ((dp=opendir(path))==NULL)
		return;
	while ((entry=readdir(dp)) != NULL) {
		if (strcmp(".",entry->d_name) == 0 || strcmp("..",entry->d_name) == 0)
			continue;
		snprintf(pathbuffer,65535,"%s/%s",path,entry->d_name);
		multiscan(pathbuffer);
	}
	closedir(dp);
}

int endswith(char * str, char * needle) {
	int ln=strlen(needle);
	int ls=strlen(str);
	return (ls > ln && !strcmp(str + ls - ln, needle));
}

void multiscan(char *path) {
	struct stat statbuf;
	lstat(path,&statbuf);
	if (S_ISDIR(statbuf.st_mode)) 
		scan_dir(path);
	else if (endswith(path,".php"))
		scanfile(path);
}

void compile_rules(char * m) {
	char * p=m;
	char * e;
	char * nam, *quick, *regex;
	for (;;) {
		for (e=p; (*e)!=0 && (*e)!='\n'; e++)
			;
		if (e==p)
			break;
		*e=0;
		nam=strtok(p,"\t");
		quick=strtok(NULL,"\t");
		regex=strtok(NULL,"\t");
		add_rule(nam,quick,regex);
		p=e+1;
	}
}
#include <curl/curl.h>
 
struct memory_struct {
	char *memory;
	size_t size;
};
 
static size_t
write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct memory_struct *mem = (struct memory_struct *)userp;
	
	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
		/* out of memory! */ 
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}
	
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	
	return realsize;
}

int fetch_rules(const char * url) {
	CURL *curl_handle;
	CURLcode res;
	int ret=0;
	struct memory_struct chunk;
 
	chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
	chunk.size = 0;    /* no data at this point */ 
 
	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_memory_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	res = curl_easy_perform(curl_handle);
 
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		ret=0;
	}
	else {
	/*
	* Now, our chunk.memory points to a memory block that is chunk.size
	* bytes big and contains the remote file.
	*
	* Do something nice with it!
	*/ 
		chunk.memory[chunk.size]=0;
		compile_rules(chunk.memory);
		ret=1;
	}
	curl_easy_cleanup(curl_handle);
	free(chunk.memory);
	curl_global_cleanup();
	
	return ret;
}



int main(int argc, char ** argv)
{
if (!fetch_rules("http://ickx.interac.it/scan/rules.txt")) {
	add_rule("EVAL_BASE", "eval","\\b(eval)\\b.+\\b(base64_decode)\\b");
	add_rule("STOP_","stop_","\\b(stop_)\\b");
	add_rule("PCT4BA6ODSE_","PCT4BA6ODSE_","\\b(PCT4BA6ODSE_)\\b");
	add_rule("MOVE_UPLOADED_FILE","move_uploaded_file","\\bmove_uploaded_file\\b.*\\bsecurity_code\\b");
	add_rule("EVAL.V","eval","\\b(eval.v)\\b");
	add_rule("MAINERROR","mainerror","\\b(mainerror)\\b");
	add_rule("GLOBAL3","GLOBALS","\\b(GLOBALS)\\b.*\\b(GLOBALS).*\\b(GLOBALS)");
	add_rule("EVAL_GLOBAL","eval","\\b(eval)\\b.*\\b(GLOBALS)\\b");
	add_rule("PREG_REPLACE1","preg_replace","\\b(preg_replace).(STR_CONSTANT)\\b");
	add_rule("PREG_REPLACE2","preg_replace","@preg_replace\\b");
	add_rule("CHR8","chr","(\\b(chr)\\b.*){8,}");
	add_rule("BASE64","base64decode","=(['\\\"])base64_decode(\\1)");
	add_rule("ISSET_EVAL","eval","\\b(strto.*)\\b(if)\\b.*\\b(isset)\\b.*\\b(eval)\\b.*");
	add_rule("INCLUDE","include","\\*\\/include\\/\\*");
	add_rule("GLOBAL2","GLOBALS","GLOBALS.*;global\\$[a-z][a-f0-9]+\\b.*GLOBALS");
	add_rule("COOKIE","COOKIE","^\\$[a-z]+=\\$_COOKIE\\s*;");
	}

multiscan(argv[1]);
}
