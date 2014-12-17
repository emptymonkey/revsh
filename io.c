
#ifdef OPENSSL

#include "io_ssl.c"

#else

#include "io_nossl.c"

#endif /* OPENSSL */


/***********************************************************************************************************************
 *
 * remote_printf()
 *
 * Input: A pointer to our io_helper object, and the fmt specification as you would find in a normal printf
 *  statement.
 * Output: The count of characters succesfully printed.
 *
 * Purpose: Provide a printf() style wrapper that will do the right thing down our socket.
 *
 **********************************************************************************************************************/
int remote_printf(struct io_helper *io, char *fmt, ...){

  int retval;
  char buff[BUFFER_SIZE];
  va_list list_ptr;


  va_start(list_ptr, fmt);

  /* XXX Add a loop here in case we need to print something longer than BUFFER_SIZE. */
  memset(buff, 0, BUFFER_SIZE);
  if((retval = vsnprintf(buff, BUFFER_SIZE - 1, fmt, list_ptr)) < 0){
    print_error(io, "%s: %d: vsnprintf(%lx, %d, %lx, %lx): %s\n", \
        program_invocation_short_name, io->controller, \
        (unsigned long) buff, BUFFER_SIZE - 1, (unsigned long) fmt, (unsigned long) list_ptr, \
        strerror(errno));
    return(retval);
  }
  io->remote_write(io, buff, retval + 1);

  va_end(list_ptr);

  return(retval);
}



/***********************************************************************************************************************
 *
 * print_error()
 *
 * Input: A pointer to our io_helper object, and the fmt specification as you would find in a normal printf
 *  statement.
 * Output: The count of characters succesfully printed.
 *
 * Purpose: Provide a wrapper that allows us to just call print_error() and have the correct thing happen regardless of
 *  being a target or a controller. This simplifies the error reporting code greatly.
 *
 **********************************************************************************************************************/
int print_error(struct io_helper *io, char *fmt, ...){

  int retval = 0;
  va_list list_ptr;


  va_start(list_ptr, fmt);

  if(io->controller){
    if((retval = vfprintf(stderr, fmt, list_ptr)) < 0){
      print_error(io, "%s: %d: vfprintf(stderr, %lx, %lx): %s\n", \
          program_invocation_short_name, io->controller, \
          (unsigned long) fmt, (unsigned long) list_ptr, \
          strerror(errno));
    }
    fflush(stderr);
  }else{
    retval = remote_printf(io, fmt, list_ptr);
  }

  return(retval);
}


/*******************************************************************************
 * 
 * catch_alarm()
 *
 * Input: The signal being handled. (SIGALRM)
 * Output: None. 
 * 
 * Purpose: To catch SIGALRM and exit quietly.
 * 
 ******************************************************************************/
void catch_alarm(int signal){
  exit(-signal);
}

