#include <stdio.h>
#include <mysql/my_global.h>
#include <mysql/my_byteorder.h>
#include <mysql/mysql.h>

int main(int argc, char **argv)
{
  MYSQL *con = mysql_init(NULL);
  
  if(con == NULL){
	fprintf(stderr, "%s\n first if", mysql_error(con));
	exit(1);
  }
  
  if (mysql_real_connect(con, "localhost", "root", "iman3000", 
          NULL, 0, NULL, 0) == NULL) 
  {
      fprintf(stderr, "%s\n second if", mysql_error(con));
      mysql_close(con);
      exit(1);
  }  

  if (mysql_query(con, "CREATE DATABASE testdb")) 
  {
      fprintf(stderr, "%s\n third if", mysql_error(con));
      mysql_close(con);
      exit(1);
  }

  mysql_close(con);
  exit(0);
}

