#include <string.h>          /* strlen */
#include <stdio.h>           /* printf */
#include <stdlib.h>          /* malloc */

/* Include the hash table (would normally be #include <ght_hash_table.h> but we
   want to be sure to include the one in this directory here) */
#include "ght_hash_table.h"

/* This is a very short example of the usage of the hash table */
int main(int argc, char *argv[])
{
  ght_hash_table_t *p_table;
  int *p_data;
  int *p_he;

  p_table = ght_create(128);

  if ( !(p_data = (int*)malloc(sizeof(int))) )
    return -1;
  /* Assign the data a value */
  *p_data = 15;

  /* Insert "blabla" into the hash table */
  ght_insert(p_table,
	     p_data,
	     sizeof(char)*strlen("blabla"), "blabla");

  /* Search for "blabla" */
  if ( (p_he = ght_get(p_table,
		       sizeof(char)*strlen("blabla"), "blabla")) )
    printf("Found %d\n", *p_he);
  else
    printf("Did not find anything!\n");

  /* Remove the hash table */
  ght_finalize(p_table);

  return 0;
}