/*****************************************************************************
This program will read a file in memory using a queue, substitute a given
string with an other string and overwrite the file. In a sense it is a custom
inline sed. It was developed as part of the MSI installer so that nxlog.conf
will be updated with a user defined ROOT path. Typically it is called with
the arguments: "[INSTALLDIR]conf\nxlog.conf" "C:\Program Files\nxlog"
"[INSTALLDIR]". The first argument is the file to modify, the second the
string to search and replace and the third the new string to replace the old
one (minus one char! because it uses to remove trailed slash).
The fourth argument is optional and used as a flag.
Flags:
 -w : replace if only whole line is match
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define bufSize 256

struct Node
{
   char* str;
   struct Node *next;
};

struct Queue {
	struct Node *head;
	struct Node *tail;
	int size;
} QUEUE;

void insert(char *str)
{
	struct Node *tmp;
	tmp = (struct Node *)malloc(sizeof(struct Node));

	tmp->str = str;
	tmp->next = NULL;

	if (QUEUE.tail == NULL)
	{
		QUEUE.head = QUEUE.tail = tmp;
	}
	else
	{
		QUEUE.tail->next = tmp;
		QUEUE.tail = tmp;
	}
	QUEUE.size++;
}

char *extract()
{
	struct Node *tmp;
	char *str = NULL;

	tmp = QUEUE.head;

	if (QUEUE.head == NULL)
	{
		QUEUE.head = QUEUE.tail = NULL;
		QUEUE.size = 0;
	}
	else
	{
		QUEUE.head = QUEUE.head->next;
		str = tmp->str;
		free (tmp);
		QUEUE.size--;
	}
	return str;
}

void initqueue()
{
	QUEUE.head = QUEUE.tail = NULL;
	QUEUE.size = 0;
}

char *replace_str(char *str, char *orig, char *repl)
{
  static char buffer[bufSize];
  char *p;

  if(!(p = strstr(str, orig)))
    return str;

  strncpy(buffer, str, p-str);
  buffer[p-str] = '\0';

  sprintf(buffer+(p-str), "%s%s", repl, p+strlen(orig));

  return buffer;
}

char *replace_str_w(char *str, char *orig, char *repl)
{
  static char buffer[bufSize];

  strncpy(buffer, str, strlen(str));
  buffer[strcspn(buffer,"\r\n")]='\0';

  if (strcmp(buffer, orig)==0) {
    return replace_str(str, orig, repl);
  } else {
    return str;
  }
}


int main(int argc, char *argv[])
{
  FILE* in;
  FILE* out;
  static char buffer[bufSize];
  char replace[bufSize];
  char *tmp;
  int i;
  char* (*replace_f) (char *, char *, char *); // replace function

  if (argc < 4)
  {
	  printf("Incorrect number of arguments\n");
	  return 1;
  }

  //Zero out the array
  for (i=0; i < bufSize; i++)
  {
	  replace[i] = '\0';
  }
  //Remove trailing slash from the path
  strncpy(replace,argv[3],strlen(argv[3])-1);

  #ifdef DEBUG
  printf("Arguments are: %s %s %s\n", argv[1], argv[2], argv[3]);
  #endif

  initqueue();

  if ((in = fopen(argv[1], "r")) == NULL)
  {
    perror("Could not open input file");
    return 1;
  }

  // detect whole line flag
  if ((argc > 4) && (strcmp(argv[4],"-w")==0)) {
	  replace_f=replace_str_w;
  } else {
	  replace_f=replace_str;
  }

  while (fgets(buffer, sizeof(buffer), in) != NULL)
  {
	tmp = (char *)malloc(sizeof(buffer));
	strncpy(tmp, replace_f(buffer, argv[2], replace), sizeof(buffer));
	insert(tmp);
  }

  fclose(in);

  if ((out = fopen(argv[1], "w")) == NULL)
  {
    perror("Could not open output file");
    return 1;
  }

  while ((tmp = extract()) != NULL)
  {
	fputs(tmp,out);
	free(tmp);
  }


  fclose(out);

  #ifdef DEBUG
  printf("Hit any key to continue...\n");
  getchar();
  #endif

  return 0;
}
