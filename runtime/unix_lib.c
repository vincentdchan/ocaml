/**************************************************************************/
/*                                                                        */
/*                                 OCaml                                  */
/*                                                                        */
/*             Xavier Leroy, projet Cristal, INRIA Rocquencourt           */
/*                                                                        */
/*   Copyright 1996 Institut National de Recherche en Informatique et     */
/*     en Automatique.                                                    */
/*                                                                        */
/*   All rights reserved.  This file is distributed under the terms of    */
/*   the GNU Lesser General Public License version 2.1, with the          */
/*   special exception on linking described in the file LICENSE.          */
/*                                                                        */
/**************************************************************************/

#define _GNU_SOURCE
#define CAML_INTERNALS
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stddef.h>
#include "caml/mlvalues.h"
#include "caml/alloc.h"
#include "caml/fail.h"
#include "caml/io.h"
#include "caml/memory.h"
#include "caml/signals.h"
#include "caml/config.h"
#include "caml/debugger.h"
#include "caml/eventlog.h"
#include "caml/fail.h"
#include "caml/custom.h"
#include "caml/bigarray.h"
#include "unixsupport.h"
#include "cst2constr.h"

#ifdef HAS_UNISTD
#include <unistd.h>
#endif
#include <sys/types.h>
#ifdef HAS_GETAUXVAL
#include <sys/auxv.h>
#endif

#ifdef HAS_SOCKETS

#include "socketaddr.h"

CAMLprim value unix_accept(value cloexec, value sock)
{
  int retcode;
  value res;
  value a;
  union sock_addr_union addr;
  socklen_param_type addr_len;
  int clo = unix_cloexec_p(cloexec);

  addr_len = sizeof(addr);
  caml_enter_blocking_section();
#if defined(HAS_ACCEPT4) && defined(SOCK_CLOEXEC)
  retcode = accept4(Int_val(sock), &addr.s_gen, &addr_len,
                    clo ? SOCK_CLOEXEC : 0);
#else
  retcode = accept(Int_val(sock), &addr.s_gen, &addr_len);
#endif
  caml_leave_blocking_section();
  if (retcode == -1) uerror("accept", Nothing);
#if !(defined(HAS_ACCEPT4) && defined(SOCK_CLOEXEC))
  if (clo) unix_set_cloexec(retcode, "accept", Nothing);
#endif
  a = alloc_sockaddr(&addr, addr_len, retcode);
  Begin_root (a);
    res = caml_alloc_small(2, 0);
    Field(res, 0) = Val_int(retcode);
    Field(res, 1) = a;
  End_roots();
  return res;
}

#else

CAMLprim value unix_accept(value cloexec, value sock)
{ caml_invalid_argument("accept not implemented"); }

#endif

#ifdef HAS_UNISTD
# include <unistd.h>
#else
# ifndef _WIN32
#  include <sys/file.h>
# endif
# ifndef R_OK
#   define R_OK    4/* test for read permission */
#   define W_OK    2/* test for write permission */
#   define X_OK    1/* test for execute (search) permission */
#   define F_OK    0/* test for presence of file */
# endif
#endif

static int access_permission_table[] = {
  R_OK,
  W_OK,
#ifdef _WIN32
  /* Since there is no concept of execute permission on Windows,
     we fall b+ack to the read permission */
  R_OK,
#else
  X_OK,
#endif
  F_OK
};

CAMLprim value unix_access(value path, value perms)
{
  CAMLparam2(path, perms);
  char_os * p;
  int ret, cv_flags;

  caml_unix_check_path(path, "access");
  cv_flags = caml_convert_flag_list(perms, access_permission_table);
  p = caml_stat_strdup_to_os(String_val(path));
  caml_enter_blocking_section();
  ret = access_os(p, cv_flags);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1)
    uerror("access", path);
  CAMLreturn(Val_unit);
}

#ifdef HAS_SOCKETS

CAMLprim value unix_inet_addr_of_string(value s)
{
  if (! caml_string_is_c_safe(s)) caml_failwith("inet_addr_of_string");
#if defined(HAS_IPV6)
#ifdef _WIN32
 {
  CAMLparam1(s);
  CAMLlocal1(vres);
  struct addrinfo hints;
  struct addrinfo * res;
  int retcode;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;
  retcode = getaddrinfo(String_val(s), NULL, &hints, &res);
  if (retcode != 0) caml_failwith("inet_addr_of_string");
  switch (res->ai_addr->sa_family) {
  case AF_INET:
    {
      vres =
        alloc_inet_addr(&((struct sockaddr_in *) res->ai_addr)->sin_addr);
      break;
    }
  case AF_INET6:
    {
      vres =
        alloc_inet6_addr(&((struct sockaddr_in6 *) res->ai_addr)->sin6_addr);
      break;
    }
  default:
    {
      freeaddrinfo(res);
      caml_failwith("inet_addr_of_string");
    }
  }
  freeaddrinfo(res);
  CAMLreturn (vres);
 }
#else
 {
  struct in_addr address;
  struct in6_addr address6;
  if (inet_pton(AF_INET, String_val(s), &address) > 0)
    return alloc_inet_addr(&address);
  else if (inet_pton(AF_INET6, String_val(s), &address6) > 0)
    return alloc_inet6_addr(&address6);
  else
    caml_failwith("inet_addr_of_string");
 }
#endif
#elif defined(HAS_INET_ATON)
 {
  struct in_addr address;
  if (inet_aton(String_val(s), &address) == 0)
    caml_failwith("inet_addr_of_string");
  return alloc_inet_addr(&address);
 }
#else
 {
  struct in_addr address;
  address.s_addr = inet_addr(String_val(s));
  if (address.s_addr == (uint32_t) -1) caml_failwith("inet_addr_of_string");
  return alloc_inet_addr(&address);
 }
#endif
}

#else

CAMLprim value unix_inet_addr_of_string(value s)
{ caml_invalid_argument("inet_addr_of_string not implemented"); }

#endif

CAMLprim value unix_alarm(value t)
{
  return Val_int(alarm((unsigned int) Long_val(t)));
}

#ifdef HAS_SOCKETS

CAMLprim value unix_bind(value socket, value address)
{
  int ret;
  union sock_addr_union addr;
  socklen_param_type addr_len;

  get_sockaddr(address, &addr, &addr_len);
  ret = bind(Int_val(socket), &addr.s_gen, addr_len);
  if (ret == -1) uerror("bind", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_bind(value socket, value address)
{ caml_invalid_argument("bind not implemented"); }

#endif

/* Check that the given file descriptor has "stream semantics" and
   can therefore be used as part of buffered I/O.  Things that
   don't have "stream semantics" include block devices and
   UDP (datagram) sockets.
   Returns 0 if OK, a nonzero error code if error. */

static int unix_check_stream_semantics(int fd)
{
  struct stat buf;

  if (fstat(fd, &buf) == -1) return errno;
  switch (buf.st_mode & S_IFMT) {
  case S_IFREG: case S_IFCHR: case S_IFIFO:
    /* These have stream semantics */
    return 0;
#ifdef HAS_SOCKETS
  case S_IFSOCK: {
    int so_type;
    socklen_param_type so_type_len = sizeof(so_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) == -1)
      return errno;
    switch (so_type) {
    case SOCK_STREAM:
      return 0;
    default:
      return EINVAL;
    }
    }
#endif
  default:
    /* All other file types are suspect: block devices, directories,
       symbolic links, whatnot. */
    return EINVAL;
  }
}

CAMLprim value unix_inchannel_of_filedescr(value fd)
{
  int err;
  caml_enter_blocking_section();
  err = unix_check_stream_semantics(Int_val(fd));
  caml_leave_blocking_section();
  if (err != 0) unix_error(err, "in_channel_of_descr", Nothing);
  return caml_ml_open_descriptor_in(fd);
}

CAMLprim value unix_outchannel_of_filedescr(value fd)
{
  int err;
  caml_enter_blocking_section();
  err = unix_check_stream_semantics(Int_val(fd));
  caml_leave_blocking_section();
  if (err != 0) unix_error(err, "out_channel_of_descr", Nothing);
  return caml_ml_open_descriptor_out(fd);
}

CAMLprim value unix_chdir(value path)
{
  CAMLparam1(path);
  char_os * p;
  int ret;
  caml_unix_check_path(path, "chdir");
  p = caml_stat_strdup_to_os(String_val(path));
  caml_enter_blocking_section();
  ret = chdir_os(p);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("chdir", path);
  CAMLreturn(Val_unit);
}

CAMLprim value unix_chmod(value path, value perm)
{
  CAMLparam2(path, perm);
  char_os * p;
  int ret;
  caml_unix_check_path(path, "chmod");
  p = caml_stat_strdup_to_os(String_val(path));
  caml_enter_blocking_section();
  ret = chmod_os(p, Int_val(perm));
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("chmod", path);
  CAMLreturn(Val_unit);
}

CAMLprim value unix_chown(value path, value uid, value gid)
{
  CAMLparam1(path);
  char * p;
  int ret;
  caml_unix_check_path(path, "chown");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = chown(p, Int_val(uid), Int_val(gid));
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("chown", path);
  CAMLreturn(Val_unit);
}

CAMLprim value unix_chroot(value path)
{
  CAMLparam1(path);
  char * p;
  int ret;
  caml_unix_check_path(path, "chroot");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = chroot(p);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("chroot", path);
  CAMLreturn(Val_unit);
}

CAMLprim value unix_close(value fd)
{
  int ret;
  caml_enter_blocking_section();
  ret = close(Int_val(fd));
  caml_leave_blocking_section();
  if (ret == -1) uerror("close", Nothing);
  return Val_unit;
}

#ifdef HAS_DIRENT
#include <dirent.h>
#else
#include <sys/dir.h>
#endif

CAMLprim value unix_closedir(value vd)
{
  CAMLparam1(vd);
  DIR * d = DIR_Val(vd);
  if (d == (DIR *) NULL) unix_error(EBADF, "closedir", Nothing);
  caml_enter_blocking_section();
  closedir(d);
  caml_leave_blocking_section();
  DIR_Val(vd) = (DIR *) NULL;
  CAMLreturn(Val_unit);
}

#ifdef HAS_SOCKETS

#include "socketaddr.h"

CAMLprim value unix_connect(value socket, value address)
{
  int retcode;
  union sock_addr_union addr;
  socklen_param_type addr_len;

  get_sockaddr(address, &addr, &addr_len);
  caml_enter_blocking_section();
  retcode = connect(Int_val(socket), &addr.s_gen, addr_len);
  caml_leave_blocking_section();
  if (retcode == -1) uerror("connect", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_connect(value socket, value address)
{ caml_invalid_argument("connect not implemented"); }

#endif

char_os ** cstringvect(value arg, char * cmdname)
{
  char_os ** res;
  mlsize_t size, i;

  size = Wosize_val(arg);
  for (i = 0; i < size; i++)
    if (! caml_string_is_c_safe(Field(arg, i)))
      unix_error(EINVAL, cmdname, Field(arg, i));
  res = (char_os **) caml_stat_alloc((size + 1) * sizeof(char_os *));
  for (i = 0; i < size; i++)
    res[i] = caml_stat_strdup_to_os(String_val(Field(arg, i)));
  res[size] = NULL;
  return res;
}

void cstringvect_free(char_os ** v)
{
  int i = 0;
  while (v[i]) caml_stat_free(v[i++]);
  caml_stat_free((char *)v);
}

CAMLprim value unix_dup(value cloexec, value fd)
{
  int ret;
#ifdef F_DUPFD_CLOEXEC
  ret = fcntl(Int_val(fd),
              (unix_cloexec_p(cloexec) ? F_DUPFD_CLOEXEC : F_DUPFD),
              0);
#else
  ret = dup(Int_val(fd));
#endif
  if (ret == -1) uerror("dup", Nothing);
#ifndef F_DUPFD_CLOEXEC
  if (unix_cloexec_p(cloexec)) unix_set_cloexec(ret, "dup", Nothing);
#endif
  return Val_int(ret);
}

#include <fcntl.h>

CAMLprim value unix_dup2(value cloexec, value fd1, value fd2)
{
  if (Int_val(fd2) == Int_val(fd1)) {
    /* In this case, dup3 fails and dup2 does nothing. */
    /* Just apply the cloexec flag to fd2, if it is given. */
    if (Is_block(cloexec)) {
      if (Bool_val(Field(cloexec, 0)))
        unix_set_cloexec(Int_val(fd2), "dup2", Nothing);
      else
        unix_clear_cloexec(Int_val(fd2), "dup2", Nothing);
    }
  } else {
#ifdef HAS_DUP3
    if (dup3(Int_val(fd1), Int_val(fd2),
             unix_cloexec_p(cloexec) ? O_CLOEXEC : 0) == -1)
      uerror("dup2", Nothing);
#else
    if (dup2(Int_val(fd1), Int_val(fd2)) == -1) uerror("dup2", Nothing);
    if (unix_cloexec_p(cloexec))
      unix_set_cloexec(Int_val(fd2), "dup2", Nothing);
#endif
  }
  return Val_unit;
}

extern char ** environ;

CAMLprim value unix_environment_unsafe(value unit)
{
  if (environ != NULL) {
    return caml_copy_string_array((const char**)environ);
  } else {
    return Atom(0);
  }
}

static char **secure_environ(void)
{
#ifdef HAS_GETAUXVAL
  if (!getauxval(AT_SECURE))
    return environ;
  else
   return NULL;
#elif defined(HAS_ISSETUGID)
  if (!issetugid ())
    return environ;
  else
    return NULL;
#else
  if (geteuid () == getuid () && getegid () == getgid ())
    return environ;
  else
    return NULL;
#endif
}

CAMLprim value unix_environment(value unit)
{
  char **e = secure_environ();
  if (e != NULL) {
    return caml_copy_string_array((const char**)e);
  } else {
    return Atom(0);
  }
}

extern int error_table[];

CAMLprim value unix_error_message(value err)
{
  int errnum;
  errnum = Is_block(err) ? Int_val(Field(err, 0)) : error_table[Int_val(err)];
  return caml_copy_string(strerror(errnum));
}

CAMLprim value unix_execv(value path, value args)
{
  char_os * wpath;
  char_os ** argv;
  caml_unix_check_path(path, "execv");
  argv = cstringvect(args, "execv");
  wpath = caml_stat_strdup_to_os(String_val(path));
  (void) execv_os(wpath, EXECV_CAST argv);
  caml_stat_free(wpath);
  cstringvect_free(argv);
  uerror("execv", path);
  return Val_unit;                  /* never reached, but suppress warnings */
                                /* from smart compilers */
}

CAMLprim value unix_execve(value path, value args, value env)
{
  char_os ** argv;
  char_os ** envp;
  char_os * wpath;
  caml_unix_check_path(path, "execve");
  argv = cstringvect(args, "execve");
  envp = cstringvect(env, "execve");
  wpath = caml_stat_strdup_to_os(String_val(path));
  (void) execve_os(wpath, EXECV_CAST argv, EXECV_CAST envp);
  caml_stat_free(wpath);
  cstringvect_free(argv);
  cstringvect_free(envp);
  uerror("execve", path);
  return Val_unit;                  /* never reached, but suppress warnings */
                                /* from smart compilers */
}

CAMLprim value unix_execvp(value path, value args)
{
  char_os ** argv;
  char_os * wpath;
  caml_unix_check_path(path, "execvp");
  argv = cstringvect(args, "execvp");
  wpath = caml_stat_strdup_to_os(String_val(path));
  (void) execvp_os((const char_os *)wpath, EXECV_CAST argv);
  caml_stat_free(wpath);
  cstringvect_free(argv);
  uerror("execvp", path);
  return Val_unit;                  /* never reached, but suppress warnings */
                                    /* from smart compilers */
}

#ifndef HAS_EXECVPE
int unix_execvpe_emulation(const char * name,
                           char * const argv[],
                           char * const envp[]);
#endif

CAMLprim value unix_execvpe(value path, value args, value env)
{
  char_os ** argv;
  char_os ** envp;
  char_os * wpath;
  int err;
  caml_unix_check_path(path, "execvpe");
  argv = cstringvect(args, "execvpe");
  envp = cstringvect(env, "execvpe");
  wpath = caml_stat_strdup_to_os(String_val(path));
#ifdef HAS_EXECVPE
  (void) execvpe_os((const char_os *)wpath, EXECV_CAST argv, EXECV_CAST envp);
  err = errno;
#else
  err = unix_execvpe_emulation(wpath, argv, envp);
#endif
  caml_stat_free(wpath);
  cstringvect_free(argv);
  cstringvect_free(envp);
  unix_error(err, "execvpe", path);
  return Val_unit;                  /* never reached, but suppress warnings */
                                    /* from smart compilers */
}

#ifndef HAS_EXECVPE

static int unix_execve_script(const char * path,
                              char * const argv[],
                              char * const envp[])
{
  size_t argc, i;
  char ** new_argv;

  /* Try executing directly.  Will not return if it succeeds. */
  execve(path, argv, envp);
  if (errno != ENOEXEC) return errno;
  /* Try executing as a shell script. */
  for (argc = 0; argv[argc] != NULL; argc++) /*skip*/;
  /* The new argument vector is
            {"/bin/sh", path, argv[1], ..., argv[argc-1], NULL} */
  new_argv = calloc(argc + 3, sizeof (char *));
  if (new_argv == NULL) return ENOMEM;
  new_argv[0] = "/bin/sh";
  new_argv[1] = (char *) path;
  for (i = 1; i < argc; i++) new_argv[i + 1] = argv[i];
  new_argv[argc + 1] = NULL;
  /* Execute the shell with the new argument vector.
     Will not return if it succeeds. */
  execve(new_argv[0], new_argv, envp);
  /* Shell execution failed. */
  free(new_argv);
  return errno;
}

int unix_execvpe_emulation(const char * name,
                           char * const argv[],
                           char * const envp[])
{
  char * searchpath, * p, * q, * fullname;
  size_t namelen, dirlen;
  int r, got_eacces;

  /* If name contains a '/', do not search in path */
  if (strchr(name, '/') != NULL) return unix_execve_script(name, argv, envp);
  /* Determine search path */
  searchpath = getenv("PATH");
  if (searchpath == NULL) searchpath = "/bin:/usr/bin";
  if (searchpath[0] == 0) return ENOENT;
  namelen = strlen(name);
  got_eacces = 0;
  p = searchpath;
  while (1) {
    /* End of path component is next ':' or end of string */
    for (q = p; *q != 0 && *q != ':'; q++) /*skip*/;
    /* Path component is between p (included) and q (excluded) */
    dirlen = q - p;
    if (dirlen == 0) {
      /* An empty path component means "current working directory" */
      r = unix_execve_script(name, argv, envp);
    } else {
      /* Construct the string "directory/name" */
      fullname = malloc(dirlen + 1 + namelen + 1);
      if (fullname == NULL) return ENOMEM;
      memcpy(fullname, p, dirlen);   /* copy directory from path */
      fullname[dirlen] = '/';        /* add separator */
      memcpy(fullname + dirlen + 1, name, namelen + 1);
                                     /* add name, including final 0 */
      r = unix_execve_script(fullname, argv, envp);
      free(fullname);
    }
    switch (r) {
    case EACCES:
      /* Record that we got a "Permission denied" error and continue. */
      got_eacces = 1; break;
    case ENOENT: case ENOTDIR:
      /* The file was not found.  Continue the search. */
      break;
    case EISDIR: case ELOOP:
    case ENODEV: case ETIMEDOUT:
      /* Strange, unexpected error.  Continue the search. */
      break;
    default:
      /* Serious error.  We found an executable file but could not
         execute it.  Stop the search and return the error. */
      return r;
    }
    /* Continue with next path component, if any */
    if (*q == 0) break;
    p = q + 1;                  /* skip ':' */
  }
  /* If we found a file but had insufficient permissions, return
     EACCES to our caller.  Otherwise, say we did not find a file
     (ENOENT). */
  return got_eacces ? EACCES : ENOENT;
}

#endif

CAMLprim value unix_exit(value n)
{
  _exit(Int_val(n));
  return Val_unit;                  /* never reached, but suppress warnings */
                                    /* from smart compilers */
}

#ifdef HAS_FCHMOD

CAMLprim value unix_fchmod(value fd, value perm)
{
  int result;
  caml_enter_blocking_section();
  result = fchmod(Int_val(fd), Int_val(perm));
  caml_leave_blocking_section();
  if (result == -1) uerror("fchmod", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_fchmod(value fd, value perm)
{ caml_invalid_argument("fchmod not implemented"); }

#endif

#ifdef HAS_FCHMOD

CAMLprim value unix_fchown(value fd, value uid, value gid)
{
  int result;
  caml_enter_blocking_section();
  result = fchown(Int_val(fd), Int_val(uid), Int_val(gid));
  caml_leave_blocking_section();
  if (result == -1) uerror("fchown", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_fchown(value fd, value uid, value gid)
{ caml_invalid_argument("fchown not implemented"); }

#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK O_NDELAY
#endif

CAMLprim value unix_set_nonblock(value fd)
{
  int retcode;
  retcode = fcntl(Int_val(fd), F_GETFL, 0);
  if (retcode == -1 ||
      fcntl(Int_val(fd), F_SETFL, retcode | O_NONBLOCK) == -1)
    uerror("set_nonblock", Nothing);
  return Val_unit;
}

CAMLprim value unix_clear_nonblock(value fd)
{
  int retcode;
  retcode = fcntl(Int_val(fd), F_GETFL, 0);
  if (retcode == -1 ||
      fcntl(Int_val(fd), F_SETFL, retcode & ~O_NONBLOCK) == -1)
    uerror("clear_nonblock", Nothing);
  return Val_unit;
}

CAMLprim value unix_set_close_on_exec(value fd)
{
  unix_set_cloexec(Int_val(fd), "set_close_on_exec", Nothing);
  return Val_unit;
}

CAMLprim value unix_clear_close_on_exec(value fd)
{
  unix_clear_cloexec(Int_val(fd), "set_close_on_exec", Nothing);
  return Val_unit;
}

CAMLprim value unix_fork(value unit)
{
  int ret;

  CAML_EV_FLUSH();

  ret = fork();
  if (ret == -1) uerror("fork", Nothing);

  CAML_EVENTLOG_DO({
      if (ret == 0)
        caml_eventlog_disable();
  });

  if (caml_debugger_in_use)
    if ((caml_debugger_fork_mode && ret == 0) ||
        (!caml_debugger_fork_mode && ret != 0))
      caml_debugger_cleanup_fork();

  return Val_int(ret);
}

#ifdef _WIN32
#include <io.h>
#define fsync(fd) _commit(fd)
#else
#define fsync(fd) fsync(fd)
#endif

CAMLprim value unix_fsync(value v)
{
  int ret;
#ifdef _WIN32
  int fd = win_CRT_fd_of_filedescr(v);
#else
  int fd = Int_val(v);
#endif
  caml_enter_blocking_section();
  ret = fsync(fd);
  caml_leave_blocking_section();
  if (ret == -1) uerror("fsync", Nothing);
  return Val_unit;
}

#ifdef HAS_TRUNCATE

CAMLprim value unix_ftruncate(value fd, value len)
{
  int result;
  caml_enter_blocking_section();
  result = ftruncate(Int_val(fd), Long_val(len));
  caml_leave_blocking_section();
  if (result == -1) uerror("ftruncate", Nothing);
  return Val_unit;
}

CAMLprim value unix_ftruncate_64(value fd, value len)
{
  int result;
  file_offset ofs = File_offset_val(len);
  caml_enter_blocking_section();
  result = ftruncate(Int_val(fd), ofs);
  caml_leave_blocking_section();
  if (result == -1) uerror("ftruncate", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_ftruncate(value fd, value len)
{ caml_invalid_argument("ftruncate not implemented"); }

CAMLprim value unix_ftruncate_64(value fd, value len)
{ caml_invalid_argument("ftruncate not implemented"); }

#endif

#if defined(HAS_SOCKETS) && defined(HAS_IPV6)

#include "socketaddr.h"
#ifndef _WIN32
#include <sys/types.h>
#include <netdb.h>
#endif

int socket_domain_table[] = {
  PF_UNIX, PF_INET,
#if defined(HAS_IPV6)
  PF_INET6
#elif defined(PF_UNDEF)
  PF_UNDEF
#else
  0
#endif
};

int socket_type_table[] = {
  SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET
};

static value convert_addrinfo(struct addrinfo * a)
{
  CAMLparam0();
  CAMLlocal3(vres,vaddr,vcanonname);
  union sock_addr_union sa;
  socklen_param_type len;

  len = a->ai_addrlen;
  if (len > sizeof(sa)) len = sizeof(sa);
  memcpy(&sa.s_gen, a->ai_addr, len);
  vaddr = alloc_sockaddr(&sa, len, -1);
  vcanonname = caml_copy_string(a->ai_canonname == NULL ? "" : a->ai_canonname);
  vres = caml_alloc_small(5, 0);
  Field(vres, 0) = cst_to_constr(a->ai_family, socket_domain_table, 3, 0);
  Field(vres, 1) = cst_to_constr(a->ai_socktype, socket_type_table, 4, 0);
  Field(vres, 2) = Val_int(a->ai_protocol);
  Field(vres, 3) = vaddr;
  Field(vres, 4) = vcanonname;
  CAMLreturn(vres);
}

CAMLprim value unix_getaddrinfo(value vnode, value vserv, value vopts)
{
  CAMLparam3(vnode, vserv, vopts);
  CAMLlocal3(vres, v, e);
  char * node, * serv;
  struct addrinfo hints;
  struct addrinfo * res, * r;
  int retcode;

  if (! (caml_string_is_c_safe(vnode) && caml_string_is_c_safe(vserv)))
    CAMLreturn (Val_int(0));

  /* Extract "node" parameter */
  if (caml_string_length(vnode) == 0) {
    node = NULL;
  } else {
    node = caml_stat_strdup(String_val(vnode));
  }
  /* Extract "service" parameter */
  if (caml_string_length(vserv) == 0) {
    serv = NULL;
  } else {
    serv = caml_stat_strdup(String_val(vserv));
  }
  /* Parse options, set hints */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  for (/*nothing*/; Is_block(vopts); vopts = Field(vopts, 1)) {
    v = Field(vopts, 0);
    if (Is_block(v))
      switch (Tag_val(v)) {
      case 0:                   /* AI_FAMILY of socket_domain */
        hints.ai_family = socket_domain_table[Int_val(Field(v, 0))];
        break;
      case 1:                   /* AI_SOCKTYPE of socket_type */
        hints.ai_socktype = socket_type_table[Int_val(Field(v, 0))];
        break;
      case 2:                   /* AI_PROTOCOL of int */
        hints.ai_protocol = Int_val(Field(v, 0));
        break;
      }
    else
      switch (Int_val(v)) {
      case 0:                   /* AI_NUMERICHOST */
        hints.ai_flags |= AI_NUMERICHOST; break;
      case 1:                   /* AI_CANONNAME */
        hints.ai_flags |= AI_CANONNAME; break;
      case 2:                   /* AI_PASSIVE */
        hints.ai_flags |= AI_PASSIVE; break;
      }
  }
  /* Do the call */
  caml_enter_blocking_section();
  retcode = getaddrinfo(node, serv, &hints, &res);
  caml_leave_blocking_section();
  if (node != NULL) caml_stat_free(node);
  if (serv != NULL) caml_stat_free(serv);
  /* Convert result */
  vres = Val_int(0);
  if (retcode == 0) {
    for (r = res; r != NULL; r = r->ai_next) {
      e = convert_addrinfo(r);
      v = caml_alloc_small(2, 0);
      Field(v, 0) = e;
      Field(v, 1) = vres;
      vres = v;
    }
    freeaddrinfo(res);
  }
  CAMLreturn(vres);
}

#else

CAMLprim value unix_getaddrinfo(value vnode, value vserv, value vopts)
{ caml_invalid_argument("getaddrinfo not implemented"); }

#endif

#if !defined (_WIN32) && !macintosh
#include <sys/param.h>
#endif

#ifndef PATH_MAX
#ifdef MAXPATHLEN
#define PATH_MAX MAXPATHLEN
#else
#define PATH_MAX 512
#endif
#endif

#ifdef HAS_GETCWD

CAMLprim value unix_getcwd(value unit)
{
  char_os buff[PATH_MAX];
  char_os * ret;
  ret = getcwd_os(buff, sizeof(buff)/sizeof(*buff));
  if (ret == 0) uerror("getcwd", Nothing);
  return caml_copy_string_of_os(buff);
}

#else

CAMLprim value unix_getcwd(value unit)
{ caml_invalid_argument("getcwd not implemented"); }

#endif

CAMLprim value unix_getegid(value unit)
{
  return Val_int(getegid());
}

CAMLprim value unix_geteuid(value unit)
{
  return Val_int(geteuid());
}

CAMLprim value unix_getgid(value unit)
{
  return Val_int(getgid());
}

#include <grp.h>

static value alloc_group_entry(struct group *entry)
{
  value res;
  value name = Val_unit, pass = Val_unit, mem = Val_unit;

  Begin_roots3 (name, pass, mem);
    name = caml_copy_string(entry->gr_name);
    /* on some platforms, namely Android, gr_passwd can be NULL,
       hence this workaround */
    pass = caml_copy_string(entry->gr_passwd ? entry->gr_passwd : "");
    mem = caml_copy_string_array((const char**)entry->gr_mem);
    res = caml_alloc_small(4, 0);
    Field(res,0) = name;
    Field(res,1) = pass;
    Field(res,2) = Val_int(entry->gr_gid);
    Field(res,3) = mem;
  End_roots();
  return res;
}

CAMLprim value unix_getgrnam(value name)
{
  struct group * entry;
  if (! caml_string_is_c_safe(name)) caml_raise_not_found();
  errno = 0;
  entry = getgrnam(String_val(name));
  if (entry == NULL) {
    if (errno == EINTR) {
      uerror("getgrnam", Nothing);
    } else {
      caml_raise_not_found();
    }
  }
  return alloc_group_entry(entry);
}

CAMLprim value unix_getgrgid(value gid)
{
  struct group * entry;
  errno = 0;
  entry = getgrgid(Int_val(gid));
  if (entry == NULL) {
    if (errno == EINTR) {
      uerror("getgrgid", Nothing);
    } else {
      caml_raise_not_found();
    }
  }
  return alloc_group_entry(entry);
}

#ifdef HAS_GETGROUPS

#include <sys/types.h>
#ifdef HAS_UNISTD
#include <unistd.h>
#endif
#include <limits.h>
#include "unixsupport.h"

CAMLprim value unix_getgroups(value unit)
{
  gid_t gidset[NGROUPS_MAX];
  int n;
  value res;
  int i;

  n = getgroups(NGROUPS_MAX, gidset);
  if (n == -1) uerror("getgroups", Nothing);
  res = caml_alloc_tuple(n);
  for (i = 0; i < n; i++)
    Field(res, i) = Val_int(gidset[i]);
  return res;
}

#else

CAMLprim value unix_getgroups(value unit)
{ caml_invalid_argument("getgroups not implemented"); }

#endif

#ifdef HAS_SOCKETS

#define NETDB_BUFFER_SIZE 10000

#ifdef _WIN32
#define GETHOSTBYADDR_IS_REENTRANT 1
#define GETHOSTBYNAME_IS_REENTRANT 1
#endif

static int entry_h_length;

extern int socket_domain_table[];

static value alloc_one_addr(char const *a)
{
  struct in_addr addr;
#ifdef HAS_IPV6
  struct in6_addr addr6;
  if (entry_h_length == 16) {
    memmove(&addr6, a, 16);
    return alloc_inet6_addr(&addr6);
  }
#endif
  memmove (&addr, a, 4);
  return alloc_inet_addr(&addr);
}

static value alloc_host_entry(struct hostent *entry)
{
  value res;
  value name = Val_unit, aliases = Val_unit;
  value addr_list = Val_unit, adr = Val_unit;

  Begin_roots4 (name, aliases, addr_list, adr);
    name = caml_copy_string((char *)(entry->h_name));
    /* PR#4043: protect against buggy implementations of gethostbyname()
       that return a NULL pointer in h_aliases */
    if (entry->h_aliases)
      aliases = caml_copy_string_array((const char**)entry->h_aliases);
    else
      aliases = Atom(0);
    entry_h_length = entry->h_length;
    addr_list =
      caml_alloc_array(alloc_one_addr, (const char**)entry->h_addr_list);
    res = caml_alloc_small(4, 0);
    Field(res, 0) = name;
    Field(res, 1) = aliases;
    switch (entry->h_addrtype) {
    case PF_UNIX:          Field(res, 2) = Val_int(0); break;
    case PF_INET:          Field(res, 2) = Val_int(1); break;
    default: /*PF_INET6 */ Field(res, 2) = Val_int(2); break;
    }
    Field(res, 3) = addr_list;
  End_roots();
  return res;
}

CAMLprim value unix_gethostbyaddr(value a)
{
  caml_invalid_argument("gethostbyaddr not implemented");
}

CAMLprim value unix_gethostbyname(value name)
{
  struct hostent * hp;
  char * hostname;
#if HAS_GETHOSTBYNAME_R
  struct hostent h;
  char buffer[NETDB_BUFFER_SIZE];
  int err;
#endif

  if (! caml_string_is_c_safe(name)) caml_raise_not_found();

  hostname = caml_stat_strdup(String_val(name));

#if HAS_GETHOSTBYNAME_R == 5
  {
    caml_enter_blocking_section();
    hp = gethostbyname_r(hostname, &h, buffer, sizeof(buffer), &err);
    caml_leave_blocking_section();
  }
#elif HAS_GETHOSTBYNAME_R == 6
  {
    int rc;
    caml_enter_blocking_section();
    rc = gethostbyname_r(hostname, &h, buffer, sizeof(buffer), &hp, &err);
    caml_leave_blocking_section();
    if (rc != 0) hp = NULL;
  }
#else
#ifdef GETHOSTBYNAME_IS_REENTRANT
  caml_enter_blocking_section();
#endif
  hp = gethostbyname(hostname);
#ifdef GETHOSTBYNAME_IS_REENTRANT
  caml_leave_blocking_section();
#endif
#endif

  caml_stat_free(hostname);

  if (hp == (struct hostent *) NULL) caml_raise_not_found();
  return alloc_host_entry(hp);
}

#else

CAMLprim value unix_gethostbyaddr(value name)
{ caml_invalid_argument("gethostbyaddr not implemented"); }

CAMLprim value unix_gethostbyname(value name)
{ caml_invalid_argument("gethostbyname not implemented"); }

#endif

#ifdef HAS_GETHOSTNAME

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

CAMLprim value unix_gethostname(value unit)
{
  char name[MAXHOSTNAMELEN];
  gethostname(name, MAXHOSTNAMELEN);
  name[MAXHOSTNAMELEN-1] = 0;
  return caml_copy_string(name);
}

#else
#ifdef HAS_UNAME

#include <sys/utsname.h>

CAMLprim value unix_gethostname(value unit)
{
  struct utsname un;
  uname(&un);
  return copy_string(un.nodename);
}

#else

CAMLprim value unix_gethostname(value unit)
{ caml_invalid_argument("gethostname not implemented"); }

#endif
#endif

extern char * getlogin(void);

CAMLprim value unix_getlogin(value unit)
{
  char * name;
  name = getlogin();
  if (name == NULL) unix_error(ENOENT, "getlogin", Nothing);
  return caml_copy_string(name);
}

#if defined(HAS_SOCKETS) && defined(HAS_IPV6)

#include "socketaddr.h"
#ifndef _WIN32
#include <sys/types.h>
#include <netdb.h>
#endif

static int getnameinfo_flag_table[] = {
  NI_NOFQDN, NI_NUMERICHOST, NI_NAMEREQD, NI_NUMERICSERV, NI_DGRAM
};

CAMLprim value unix_getnameinfo(value vaddr, value vopts)
{
  CAMLparam0();
  CAMLlocal3(vhost, vserv, vres);
  union sock_addr_union addr;
  socklen_param_type addr_len;
  char host[4096];
  char serv[1024];
  int opts, retcode;

  get_sockaddr(vaddr, &addr, &addr_len);
  opts = caml_convert_flag_list(vopts, getnameinfo_flag_table);
  caml_enter_blocking_section();
  retcode =
    getnameinfo((const struct sockaddr *) &addr.s_gen, addr_len,
                host, sizeof(host), serv, sizeof(serv), opts);
  caml_leave_blocking_section();
  /* TODO: detailed error reporting? */
  if (retcode != 0) caml_raise_not_found();
  vhost = caml_copy_string(host);
  vserv = caml_copy_string(serv);
  vres = caml_alloc_small(2, 0);
  Field(vres, 0) = vhost;
  Field(vres, 1) = vserv;
  CAMLreturn(vres);
}

#else

CAMLprim value unix_getnameinfo(value vaddr, value vopts)
{ caml_invalid_argument("getnameinfo not implemented"); }

#endif

#ifdef HAS_SOCKETS

#include "socketaddr.h"

CAMLprim value unix_getpeername(value sock)
{
  int retcode;
  union sock_addr_union addr;
  socklen_param_type addr_len;

  addr_len = sizeof(addr);
  retcode = getpeername(Int_val(sock), &addr.s_gen, &addr_len);
  if (retcode == -1) uerror("getpeername", Nothing);
  return alloc_sockaddr(&addr, addr_len, -1);
}

#else

CAMLprim value unix_getpeername(value sock)
{ caml_invalid_argument("getpeername not implemented"); }

#endif

CAMLprim value unix_getpid(value unit)
{
  return Val_int(getpid());
}

CAMLprim value unix_getppid(value unit)
{
  return Val_int(getppid());
}

#ifdef HAS_SOCKETS

#ifndef _WIN32
#include <netdb.h>
#endif

static value alloc_proto_entry(struct protoent *entry)
{
  value res;
  value name = Val_unit, aliases = Val_unit;

  Begin_roots2 (name, aliases);
    name = caml_copy_string(entry->p_name);
    aliases = caml_copy_string_array((const char**)entry->p_aliases);
    res = caml_alloc_small(3, 0);
    Field(res,0) = name;
    Field(res,1) = aliases;
    Field(res,2) = Val_int(entry->p_proto);
  End_roots();
  return res;
}

CAMLprim value unix_getprotobyname(value name)
{
  struct protoent * entry;
  if (! caml_string_is_c_safe(name)) caml_raise_not_found();
  entry = getprotobyname(String_val(name));
  if (entry == (struct protoent *) NULL) caml_raise_not_found();
  return alloc_proto_entry(entry);
}

CAMLprim value unix_getprotobynumber(value proto)
{
  struct protoent * entry;
  entry = getprotobynumber(Int_val(proto));
  if (entry == (struct protoent *) NULL) caml_raise_not_found();
  return alloc_proto_entry(entry);
}

#else

CAMLprim value unix_getprotobynumber(value proto)
{ caml_invalid_argument("getprotobynumber not implemented"); }

CAMLprim value unix_getprotobyname(value name)
{ caml_invalid_argument("getprotobyname not implemented"); }

#endif

CAMLprim value unix_getpwnam(value name)
{
  caml_invalid_argument("getpwnam not implemented");
}

CAMLprim value unix_getpwuid(value uid)
{
  caml_invalid_argument("getpwuid not implemented");
}

#ifdef HAS_SOCKETS

static value alloc_service_entry(struct servent *entry)
{
  value res;
  value name = Val_unit, aliases = Val_unit, proto = Val_unit;

  Begin_roots3 (name, aliases, proto);
    name = caml_copy_string(entry->s_name);
    aliases = caml_copy_string_array((const char**)entry->s_aliases);
    proto = caml_copy_string(entry->s_proto);
    res = caml_alloc_small(4, 0);
    Field(res,0) = name;
    Field(res,1) = aliases;
    Field(res,2) = Val_int(ntohs(entry->s_port));
    Field(res,3) = proto;
  End_roots();
  return res;
}

CAMLprim value unix_getservbyname(value name, value proto)
{
  struct servent * entry;
  if (! (caml_string_is_c_safe(name) && caml_string_is_c_safe(proto)))
    caml_raise_not_found();
  entry = getservbyname(String_val(name), String_val(proto));
  if (entry == (struct servent *) NULL) caml_raise_not_found();
  return alloc_service_entry(entry);
}

CAMLprim value unix_getservbyport(value port, value proto)
{
  struct servent * entry;
  if (! caml_string_is_c_safe(proto)) caml_raise_not_found();
  entry = getservbyport(htons(Int_val(port)), String_val(proto));
  if (entry == (struct servent *) NULL) caml_raise_not_found();
  return alloc_service_entry(entry);
}

#else

CAMLprim value unix_getservbyport(value port, value proto)
{ caml_invalid_argument("getservbyport not implemented"); }

CAMLprim value unix_getservbyname(value name, value proto)
{ caml_invalid_argument("getservbyname not implemented"); }

#endif

#ifdef HAS_SOCKETS

#include "socketaddr.h"

CAMLprim value unix_getsockname(value sock)
{
  int retcode;
  union sock_addr_union addr;
  socklen_param_type addr_len;

  addr_len = sizeof(addr);
  retcode = getsockname(Int_val(sock), &addr.s_gen, &addr_len);
  if (retcode == -1) uerror("getsockname", Nothing);
  return alloc_sockaddr(&addr, addr_len, -1);
}

#else

CAMLprim value unix_getsockname(value sock)
{ caml_invalid_argument("getsockname not implemented"); }

#endif

double unix_gettimeofday_unboxed(value unit)
{
  struct timeval tp;
  gettimeofday(&tp, NULL);
  return ((double) tp.tv_sec + (double) tp.tv_usec / 1e6);
}

CAMLprim value unix_gettimeofday(value unit)
{
  return caml_copy_double(unix_gettimeofday_unboxed(unit));
}

CAMLprim value unix_getuid(value unit)
{
  return Val_int(getuid());
}

static value alloc_tm(struct tm *tm)
{
  value res;
  res = caml_alloc_small(9, 0);
  Field(res,0) = Val_int(tm->tm_sec);
  Field(res,1) = Val_int(tm->tm_min);
  Field(res,2) = Val_int(tm->tm_hour);
  Field(res,3) = Val_int(tm->tm_mday);
  Field(res,4) = Val_int(tm->tm_mon);
  Field(res,5) = Val_int(tm->tm_year);
  Field(res,6) = Val_int(tm->tm_wday);
  Field(res,7) = Val_int(tm->tm_yday);
  Field(res,8) = tm->tm_isdst ? Val_true : Val_false;
  return res;
}

CAMLprim value unix_gmtime(value t)
{
  time_t clock;
  struct tm * tm;
  clock = (time_t) Double_val(t);
  tm = gmtime(&clock);
  if (tm == NULL) unix_error(EINVAL, "gmtime", Nothing);
  return alloc_tm(tm);
}

CAMLprim value unix_localtime(value t)
{
  time_t clock;
  struct tm * tm;
  clock = (time_t) Double_val(t);
  tm = localtime(&clock);
  if (tm == NULL) unix_error(EINVAL, "localtime", Nothing);
  return alloc_tm(tm);
}

#ifdef HAS_MKTIME

CAMLprim value unix_mktime(value t)
{
  struct tm tm;
  time_t clock;
  value res;
  value tmval = Val_unit, clkval = Val_unit;

  Begin_roots2(tmval, clkval);
    tm.tm_sec = Int_val(Field(t, 0));
    tm.tm_min = Int_val(Field(t, 1));
    tm.tm_hour = Int_val(Field(t, 2));
    tm.tm_mday = Int_val(Field(t, 3));
    tm.tm_mon = Int_val(Field(t, 4));
    tm.tm_year = Int_val(Field(t, 5));
    tm.tm_wday = Int_val(Field(t, 6));
    tm.tm_yday = Int_val(Field(t, 7));
    tm.tm_isdst = -1; /* tm.tm_isdst = Bool_val(Field(t, 8)); */
    clock = mktime(&tm);
    if (clock == (time_t) -1) unix_error(ERANGE, "mktime", Nothing);
    tmval = alloc_tm(&tm);
    clkval = caml_copy_double((double) clock);
    res = caml_alloc_small(2, 0);
    Field(res, 0) = clkval;
    Field(res, 1) = tmval;
  End_roots ();
  return res;
}

#else

CAMLprim value unix_mktime(value t)
{ caml_invalid_argument("mktime not implemented"); }

#endif

#ifdef HAS_INITGROUPS

#include <sys/types.h>
#ifdef HAS_UNISTD
#include <unistd.h>
#endif
#include <errno.h>
#include <limits.h>
#include <grp.h>
#include "unixsupport.h"

CAMLprim value unix_initgroups(value user, value group)
{
  if (! caml_string_is_c_safe(user))
    unix_error(EINVAL, "initgroups", user);
  if (initgroups(String_val(user), Int_val(group)) == -1) {
    uerror("initgroups", Nothing);
  }
  return Val_unit;
}

#else

CAMLprim value unix_initgroups(value user, value group)
{ caml_invalid_argument("initgroups not implemented"); }

#endif

CAMLprim value unix_isatty(value fd)
{
  return (Val_bool(isatty(Int_val(fd))));
}

#ifdef HAS_SETITIMER

#include <math.h>
#include <sys/time.h>

static void unix_set_timeval(struct timeval * tv, double d)
{
  double integr, frac;
  frac = modf(d, &integr);
  /* Round time up so that if d is small but not 0, we end up with
     a non-0 timeval. */
  tv->tv_sec = integr;
  tv->tv_usec = ceil(1e6 * frac);
  if (tv->tv_usec >= 1000000) { tv->tv_sec++; tv->tv_usec = 0; }
}

static value unix_convert_itimer(struct itimerval *tp)
{
#define Get_timeval(tv) (double) tv.tv_sec + (double) tv.tv_usec / 1e6
  value res = caml_alloc_small(Double_wosize * 2, Double_array_tag);
  Store_double_field(res, 0, Get_timeval(tp->it_interval));
  Store_double_field(res, 1, Get_timeval(tp->it_value));
  return res;
#undef Get_timeval
}

static int itimers[3] = { ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF };

CAMLprim value unix_setitimer(value which, value newval)
{
  struct itimerval new, old;
  unix_set_timeval(&new.it_interval, Double_field(newval, 0));
  unix_set_timeval(&new.it_value, Double_field(newval, 1));
  if (setitimer(itimers[Int_val(which)], &new, &old) == -1)
    uerror("setitimer", Nothing);
  return unix_convert_itimer(&old);
}

CAMLprim value unix_getitimer(value which)
{
  struct itimerval val;
  if (getitimer(itimers[Int_val(which)], &val) == -1)
    uerror("getitimer", Nothing);
  return unix_convert_itimer(&val);
}

#else

CAMLprim value unix_setitimer(value which, value newval)
{ caml_invalid_argument("setitimer not implemented"); }
CAMLprim value unix_getitimer(value which)
{ caml_invalid_argument("getitimer not implemented"); }

#endif

CAMLprim value unix_kill(value pid, value signal)
{
  int sig;
  sig = caml_convert_signal_number(Int_val(signal));
  if (kill(Int_val(pid), sig) == -1)
    uerror("kill", Nothing);
  caml_process_pending_actions();
  return Val_unit;
}

CAMLprim value unix_link(value follow, value path1, value path2)
{
  CAMLparam3(follow, path1, path2);
  char * p1;
  char * p2;
  int ret;
  caml_unix_check_path(path1, "link");
  caml_unix_check_path(path2, "link");
  p1 = caml_stat_strdup(String_val(path1));
  p2 = caml_stat_strdup(String_val(path2));
  caml_enter_blocking_section();
  if (follow == Val_int(0) /* None */)
    ret = link(p1, p2);
  else { /* Some bool */
# ifdef AT_SYMLINK_FOLLOW
    int flags =
      Is_block(follow) && Bool_val(Field(follow, 0)) /* Some true */
      ? AT_SYMLINK_FOLLOW
      : 0;
    ret = linkat(AT_FDCWD, p1, AT_FDCWD, p2, flags);
# else
    ret = -1; errno = ENOSYS;
# endif
  }
  caml_leave_blocking_section();
  caml_stat_free(p1);
  caml_stat_free(p2);
  if (ret == -1) uerror("link", path2);
  CAMLreturn(Val_unit);
}

#ifdef HAS_SOCKETS

#include <sys/socket.h>

CAMLprim value unix_listen(value sock, value backlog)
{
  if (listen(Int_val(sock), Int_val(backlog)) == -1) uerror("listen", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_listen(value sock, value backlog)
{ caml_invalid_argument("listen not implemented"); }

#endif

#if defined(F_GETLK) && defined(F_SETLK) && defined(F_SETLKW)

CAMLprim value unix_lockf(value fd, value cmd, value span)
{
  struct flock l;
  int ret;
  int fildes;
  long size;

  fildes = Int_val(fd);
  size = Long_val(span);
  l.l_whence = 1;
  if (size < 0) {
    l.l_start = size;
    l.l_len = -size;
  } else {
    l.l_start = 0L;
    l.l_len = size;
  }
  switch (Int_val(cmd)) {
  case 0: /* F_ULOCK */
    l.l_type = F_UNLCK;
    ret = fcntl(fildes, F_SETLK, &l);
    break;
  case 1: /* F_LOCK */
    l.l_type = F_WRLCK;
    caml_enter_blocking_section();
    ret = fcntl(fildes, F_SETLKW, &l);
    caml_leave_blocking_section();
    break;
  case 2: /* F_TLOCK */
    l.l_type = F_WRLCK;
    ret = fcntl(fildes, F_SETLK, &l);
    break;
  case 3: /* F_TEST */
    l.l_type = F_WRLCK;
    ret = fcntl(fildes, F_GETLK, &l);
    if (ret != -1) {
      if (l.l_type == F_UNLCK)
        ret = 0;
      else {
        errno = EACCES;
        ret = -1;
      }
    }
    break;
  case 4: /* F_RLOCK */
    l.l_type = F_RDLCK;
    caml_enter_blocking_section();
    ret = fcntl(fildes, F_SETLKW, &l);
    caml_leave_blocking_section();
    break;
  case 5: /* F_TRLOCK */
    l.l_type = F_RDLCK;
    ret = fcntl(fildes, F_SETLK, &l);
    break;
  default:
    errno = EINVAL;
    ret = -1;
  }
  if (ret == -1) uerror("lockf", Nothing);
  return Val_unit;
}

#else

#ifdef HAS_LOCKF
#ifdef HAS_UNISTD
#include <unistd.h>
#else
#define F_ULOCK 0
#define F_LOCK 1
#define F_TLOCK 2
#define F_TEST 3
#endif

static int lock_command_table[] = {
  F_ULOCK, F_LOCK, F_TLOCK, F_TEST, F_LOCK, F_TLOCK
};

CAMLprim value unix_lockf(value fd, value cmd, value span)
{
  if (lockf(Int_val(fd), lock_command_table[Int_val(cmd)], Long_val(span))
      == -1) uerror("lockf", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_lockf(value fd, value cmd, value span)
{ caml_invalid_argument("lockf not implemented"); }

#endif
#endif

#ifdef HAS_UNISTD
#include <unistd.h>
#else
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#ifndef EOVERFLOW
#define EOVERFLOW ERANGE
#endif

static int seek_command_table[] = {
  SEEK_SET, SEEK_CUR, SEEK_END
};

CAMLprim value unix_lseek(value fd, value ofs, value cmd)
{
  file_offset ret;
  caml_enter_blocking_section();
  ret = lseek(Int_val(fd), Long_val(ofs),
                       seek_command_table[Int_val(cmd)]);
  caml_leave_blocking_section();
  if (ret == -1) uerror("lseek", Nothing);
  if (ret > Max_long) unix_error(EOVERFLOW, "lseek", Nothing);
  return Val_long(ret);
}

CAMLprim value unix_lseek_64(value fd, value ofs, value cmd)
{
  file_offset ret;
  /* [ofs] is an Int64, which is stored as a custom block; we must therefore
     extract its contents before dropping the runtime lock, or it might be
     moved. */
  file_offset ofs_c = File_offset_val(ofs);
  caml_enter_blocking_section();
  ret = lseek(Int_val(fd), ofs_c, seek_command_table[Int_val(cmd)]);
  caml_leave_blocking_section();
  if (ret == -1) uerror("lseek", Nothing);
  return Val_file_offset(ret);
}

CAMLprim value unix_mkdir(value path, value perm)
{
  CAMLparam2(path, perm);
  char_os * p;
  int ret;
  caml_unix_check_path(path, "mkdir");
  p = caml_stat_strdup_to_os(String_val(path));
  caml_enter_blocking_section();
  ret = mkdir_os(p, Int_val(perm));
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("mkdir", path);
  CAMLreturn(Val_unit);
}

#ifdef HAS_MKFIFO

CAMLprim value unix_mkfifo(value path, value mode)
{
  CAMLparam2(path, mode);
  char * p;
  int ret;
  caml_unix_check_path(path, "mkfifo");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = mkfifo(p, Int_val(mode));
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1)
    uerror("mkfifo", path);
  CAMLreturn(Val_unit);
}

#else

#include <sys/types.h>
#include <sys/stat.h>

#ifdef S_IFIFO

CAMLprim value unix_mkfifo(value path, value mode)
{
  CAMLparam2(path, mode);
  char * p;
  int ret;
  caml_unix_check_path(path, "mkfifo");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = mknod(p, (Int_val(mode) & 07777) | S_IFIFO, 0);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1)
    uerror("mkfifo", path);
  CAMLreturn(Val_unit);
}

#else

CAMLprim value unix_mkfifo(value path, value mode)
{
  caml_invalid_argument("mkfifo not implemented");
}

#endif
#endif

/* Allocation of bigarrays for memory-mapped files.
   This is the OS-independent part of [mmap.c]. */

extern void caml_ba_unmap_file(void *, uintnat);

static void caml_ba_mapped_finalize(value v)
{
  struct caml_ba_array * b = Caml_ba_array_val(v);
  CAMLassert((b->flags & CAML_BA_MANAGED_MASK) == CAML_BA_MAPPED_FILE);
  if (b->proxy == NULL) {
    caml_ba_unmap_file(b->data, caml_ba_byte_size(b));
  } else {
    if (-- b->proxy->refcount == 0) {
      caml_ba_unmap_file(b->proxy->data, b->proxy->size);
      free(b->proxy);
    }
  }
}

/* Operation table for bigarrays representing memory-mapped files.
   Only the finalization method differs from regular bigarrays. */

static struct custom_operations caml_ba_mapped_ops = {
  "_bigarray",
  caml_ba_mapped_finalize,
  caml_ba_compare,
  caml_ba_hash,
  caml_ba_serialize,
  caml_ba_deserialize,
  custom_compare_ext_default,
  custom_fixed_length_default
};

/* [caml_unix_mapped_alloc] allocates a new bigarray object in the heap
   corresponding to a memory-mapped file. */

CAMLexport value
caml_unix_mapped_alloc(int flags, int num_dims, void * data, intnat * dim)
{
  uintnat asize;
  int i;
  value res;
  struct caml_ba_array * b;
  intnat dimcopy[CAML_BA_MAX_NUM_DIMS];

  CAMLassert(num_dims >= 0 && num_dims <= CAML_BA_MAX_NUM_DIMS);
  CAMLassert((flags & CAML_BA_KIND_MASK) <= CAML_BA_CHAR);
  for (i = 0; i < num_dims; i++) dimcopy[i] = dim[i];
  asize = SIZEOF_BA_ARRAY + num_dims * sizeof(intnat);
  res = caml_alloc_custom(&caml_ba_mapped_ops, asize, 0, 1);
  b = Caml_ba_array_val(res);
  b->data = data;
  b->num_dims = num_dims;
  b->flags = flags | CAML_BA_MAPPED_FILE;
  b->proxy = NULL;
  for (i = 0; i < num_dims; i++) b->dim[i] = dimcopy[i];
  return res;
}

/* Needed (under Linux at least) to get pwrite's prototype in unistd.h.
   Must be defined before the first system .h is included. */
#define _XOPEN_SOURCE 600

#ifdef HAS_UNISTD
#include <unistd.h>
#endif
#ifdef HAS_MMAP
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

/* Defined in [mmap_ba.c] */
extern value caml_unix_mapped_alloc(int, int, void *, intnat *);

#if defined(HAS_MMAP)

#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif

/* [caml_grow_file] function contributed by Gerd Stolpmann (PR#5543). */

static int caml_grow_file(int fd, file_offset size)
{
  char c;
  int p;

  /* First use pwrite for growing - it is a conservative method, as it
     can never happen that we shrink by accident
   */
#ifdef HAS_PWRITE
  c = 0;
  p = pwrite(fd, &c, 1, size - 1);
#else

  /* Emulate pwrite with lseek. This should only be necessary on ancient
     systems nowadays
   */
  file_offset currpos;
  currpos = lseek(fd, 0, SEEK_CUR);
  if (currpos != -1) {
    p = lseek(fd, size - 1, SEEK_SET);
    if (p != -1) {
      c = 0;
      p = write(fd, &c, 1);
      if (p != -1)
        p = lseek(fd, currpos, SEEK_SET);
    }
  }
  else p=-1;
#endif
#ifdef HAS_TRUNCATE
  if (p == -1 && errno == ESPIPE) {
    /* Plan B. Check if at least ftruncate is possible. There are
       some non-seekable descriptor types that do not support pwrite
       but ftruncate, like shared memory. We never get into this case
       for real files, so there is no danger of truncating persistent
       data by accident
     */
    p = ftruncate(fd, size);
  }
#endif
  return p;
}


CAMLprim value caml_unix_map_file(value vfd, value vkind, value vlayout,
                                  value vshared, value vdim, value vstart)
{
  int fd, flags, major_dim, shared;
  intnat num_dims, i;
  intnat dim[CAML_BA_MAX_NUM_DIMS];
  file_offset startpos, file_size, data_size;
  struct stat st;
  uintnat array_size, page, delta;
  void * addr;

  fd = Int_val(vfd);
  flags = Caml_ba_kind_val(vkind) | Caml_ba_layout_val(vlayout);
  startpos = File_offset_val(vstart);
  num_dims = Wosize_val(vdim);
  major_dim = flags & CAML_BA_FORTRAN_LAYOUT ? num_dims - 1 : 0;
  /* Extract dimensions from OCaml array */
  num_dims = Wosize_val(vdim);
  if (num_dims < 1 || num_dims > CAML_BA_MAX_NUM_DIMS)
    caml_invalid_argument("Unix.map_file: bad number of dimensions");
  for (i = 0; i < num_dims; i++) {
    dim[i] = Long_val(Field(vdim, i));
    if (dim[i] == -1 && i == major_dim) continue;
    if (dim[i] < 0)
      caml_invalid_argument("Unix.map_file: negative dimension");
  }
  /* Determine file size. We avoid lseek here because it is fragile,
     and because some mappable file types do not support it
   */
  caml_enter_blocking_section();
  if (fstat(fd, &st) == -1) {
    caml_leave_blocking_section();
    uerror("map_file", Nothing);
  }
  file_size = st.st_size;
  /* Determine array size in bytes (or size of array without the major
     dimension if that dimension wasn't specified) */
  array_size = caml_ba_element_size[flags & CAML_BA_KIND_MASK];
  for (i = 0; i < num_dims; i++)
    if (dim[i] != -1) array_size *= dim[i];
  /* Check if the major dimension is unknown */
  if (dim[major_dim] == -1) {
    /* Determine major dimension from file size */
    if (file_size < startpos) {
      caml_leave_blocking_section();
      caml_failwith("Unix.map_file: file position exceeds file size");
    }
    data_size = file_size - startpos;
    dim[major_dim] = (uintnat) (data_size / array_size);
    array_size = dim[major_dim] * array_size;
    if (array_size != data_size) {
      caml_leave_blocking_section();
      caml_failwith("Unix.map_file: file size doesn't match array dimensions");
    }
  } else {
    /* Check that file is large enough, and grow it otherwise */
    if (file_size < startpos + array_size) {
      if (caml_grow_file(fd, startpos + array_size) == -1) { /* PR#5543 */
        caml_leave_blocking_section();
        uerror("map_file", Nothing);
      }
    }
  }
  /* Determine offset so that the mapping starts at the given file pos */
  page = sysconf(_SC_PAGESIZE);
  delta = (uintnat) startpos % page;
  /* Do the mmap */
  shared = Bool_val(vshared) ? MAP_SHARED : MAP_PRIVATE;
  if (array_size > 0)
    addr = mmap(NULL, array_size + delta, PROT_READ | PROT_WRITE,
                shared, fd, startpos - delta);
  else
    addr = NULL;                /* PR#5463 - mmap fails on empty region */
  caml_leave_blocking_section();
  if (addr == (void *) MAP_FAILED) uerror("map_file", Nothing);
  addr = (void *) ((uintnat) addr + delta);
  /* Build and return the OCaml bigarray */
  return caml_unix_mapped_alloc(flags, num_dims, addr, dim);
}

#else

CAMLprim value caml_unix_map_file(value vfd, value vkind, value vlayout,
                                  value vshared, value vdim, value vpos)
{
  caml_invalid_argument("Unix.map_file: not supported");
  return Val_unit;
}

#endif

CAMLprim value caml_unix_map_file_bytecode(value * argv, int argn)
{
  return caml_unix_map_file(argv[0], argv[1], argv[2],
                            argv[3], argv[4], argv[5]);
}

void caml_ba_unmap_file(void * addr, uintnat len)
{
#if defined(HAS_MMAP)
  uintnat page = sysconf(_SC_PAGESIZE);
  uintnat delta = (uintnat) addr % page;
  if (len == 0) return;         /* PR#5463 */
  addr = (void *)((uintnat)addr - delta);
  len  = len + delta;
#if defined(_POSIX_SYNCHRONIZED_IO)
  msync(addr, len, MS_ASYNC);   /* PR#3571 */
#endif
  munmap(addr, len);
#endif
}

CAMLprim value unix_nice(value incr)
{
  int ret;
  errno = 0;
#ifdef HAS_NICE
  ret = nice(Int_val(incr));
#else
  ret = 0;
#endif
  if (ret == -1 && errno != 0) uerror("nice", Nothing);
  return Val_int(ret);
}

#ifndef O_NONBLOCK
#define O_NONBLOCK O_NDELAY
#endif
#ifndef O_DSYNC
#define O_DSYNC 0
#endif
#ifndef O_SYNC
#define O_SYNC 0
#endif
#ifndef O_RSYNC
#define O_RSYNC 0
#endif

static int open_flag_table[15] = {
  O_RDONLY, O_WRONLY, O_RDWR, O_NONBLOCK, O_APPEND, O_CREAT, O_TRUNC, O_EXCL,
  O_NOCTTY, O_DSYNC, O_SYNC, O_RSYNC,
  0, /* O_SHARE_DELETE, Windows-only */
  0, /* O_CLOEXEC, treated specially */
  0  /* O_KEEPEXEC, treated specially */
};

enum { CLOEXEC = 1, KEEPEXEC = 2 };

static int open_cloexec_table[15] = {
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0,
  0,
  CLOEXEC, KEEPEXEC
};

CAMLprim value unix_open(value path, value flags, value perm)
{
  CAMLparam3(path, flags, perm);
  int fd, cv_flags, clo_flags, cloexec;
  char * p;

  caml_unix_check_path(path, "open");
  cv_flags = caml_convert_flag_list(flags, open_flag_table);
  clo_flags = caml_convert_flag_list(flags, open_cloexec_table);
  if (clo_flags & CLOEXEC)
    cloexec = 1;
  else if (clo_flags & KEEPEXEC)
    cloexec = 0;
  else
    cloexec = unix_cloexec_default;
#if defined(O_CLOEXEC)
  if (cloexec) cv_flags |= O_CLOEXEC;
#endif
  p = caml_stat_strdup(String_val(path));
  /* open on a named FIFO can block (PR#8005) */
  caml_enter_blocking_section();
  fd = open(p, cv_flags, Int_val(perm));
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (fd == -1) uerror("open", path);
#if !defined(O_CLOEXEC)
  if (cloexec) unix_set_cloexec(fd, "open", path);
#endif
  CAMLreturn (Val_int(fd));
}

CAMLprim value unix_opendir(value path)
{
  CAMLparam1(path);
  DIR * d;
  value res;
  char * p;

  caml_unix_check_path(path, "opendir");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  d = opendir(p);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (d == (DIR *) NULL) uerror("opendir", path);
  res = caml_alloc_small(1, Abstract_tag);
  DIR_Val(res) = d;
  CAMLreturn(res);
}

CAMLprim value unix_pipe(value cloexec, value vunit)
{
  int fd[2];
  value res;
#ifdef HAS_PIPE2
  if (pipe2(fd, unix_cloexec_p(cloexec) ? O_CLOEXEC : 0) == -1)
    uerror("pipe", Nothing);
#else
  if (pipe(fd) == -1) uerror("pipe", Nothing);
  if (unix_cloexec_p(cloexec)) {
    unix_set_cloexec(fd[0], "pipe", Nothing);
    unix_set_cloexec(fd[1], "pipe", Nothing);
  }
#endif
  res = caml_alloc_small(2, 0);
  Field(res, 0) = Val_int(fd[0]);
  Field(res, 1) = Val_int(fd[1]);
  return res;
}

#ifdef HAS_PUTENV

CAMLprim value unix_putenv(value name, value val)
{
  char * s;
  char_os * p;
  int ret;

  if (! (caml_string_is_c_safe(name) && caml_string_is_c_safe(val)))
    unix_error(EINVAL, "putenv", name);
  s = caml_stat_strconcat(3, name, "=", val);
  p = caml_stat_strdup_to_os(s);
  caml_stat_free(s);
  ret = putenv_os(p);
  if (ret == -1) {
    caml_stat_free(p);
    uerror("putenv", name);
  }
  return Val_unit;
}

#else

CAMLprim value unix_putenv(value name, value val)
{ caml_invalid_argument("putenv not implemented"); }

#endif

CAMLprim value unix_read(value fd, value buf, value ofs, value len)
{
  long numbytes;
  int ret;
  char iobuf[UNIX_BUFFER_SIZE];

  Begin_root (buf);
    numbytes = Long_val(len);
    if (numbytes > UNIX_BUFFER_SIZE) numbytes = UNIX_BUFFER_SIZE;
    caml_enter_blocking_section();
    ret = read(Int_val(fd), iobuf, (int) numbytes);
    caml_leave_blocking_section();
    if (ret == -1) uerror("read", Nothing);
    memmove (&Byte(buf, Long_val(ofs)), iobuf, ret);
  End_roots();
  return Val_int(ret);
}

#ifdef HAS_DIRENT
#include <dirent.h>
typedef struct dirent directory_entry;
#else
#include <sys/dir.h>
typedef struct direct directory_entry;
#endif

CAMLprim value unix_readdir(value vd)
{
  DIR * d;
  directory_entry * e;
  d = DIR_Val(vd);
  if (d == (DIR *) NULL) unix_error(EBADF, "readdir", Nothing);
  caml_enter_blocking_section();
  e = readdir((DIR *) d);
  caml_leave_blocking_section();
  if (e == (directory_entry *) NULL) caml_raise_end_of_file();
  return caml_copy_string(e->d_name);
}

#ifdef HAS_SYMLINK

#include <sys/param.h>
#include "unixsupport.h"

#ifndef PATH_MAX
#ifdef MAXPATHLEN
#define PATH_MAX MAXPATHLEN
#else
#define PATH_MAX 512
#endif
#endif

CAMLprim value unix_readlink(value path)
{
  CAMLparam1(path);
  char buffer[PATH_MAX];
  int len;
  char * p;
  caml_unix_check_path(path, "readlink");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  len = readlink(p, buffer, sizeof(buffer) - 1);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (len == -1) uerror("readlink", path);
  buffer[len] = '\0';
  CAMLreturn(caml_copy_string(buffer));
}

#else

CAMLprim value unix_readlink(value path)
{ caml_invalid_argument("readlink not implemented"); }

#endif

CAMLprim value unix_rename(value path1, value path2)
{
  CAMLparam2(path1, path2);
  char * p1;
  char * p2;
  int ret;
  caml_unix_check_path(path1, "rename");
  caml_unix_check_path(path2, "rename");
  p1 = caml_stat_strdup(String_val(path1));
  p2 = caml_stat_strdup(String_val(path2));
  caml_enter_blocking_section();
  ret = rename(p1, p2);
  caml_leave_blocking_section();
  caml_stat_free(p2);
  caml_stat_free(p1);
  if (ret == -1)
    uerror("rename", path1);
  CAMLreturn(Val_unit);
}

#ifdef HAS_REWINDDIR

CAMLprim value unix_rewinddir(value vd)
{
  DIR * d = DIR_Val(vd);
  if (d == (DIR *) NULL) unix_error(EBADF, "rewinddir", Nothing);
  rewinddir(d);
  return Val_unit;
}

#else

CAMLprim value unix_rewinddir(value d)
{ caml_invalid_argument("rewinddir not implemented"); }

#endif

CAMLprim value unix_rmdir(value path)
{
  CAMLparam1(path);
  char_os * p;
  int ret;
  caml_unix_check_path(path, "rmdir");
  p = caml_stat_strdup_to_os(String_val(path));
  caml_enter_blocking_section();
  ret = rmdir_os(p);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("rmdir", path);
  CAMLreturn(Val_unit);
}

#ifdef HAS_SELECT

#include <sys/types.h>
#include <sys/time.h>
#ifdef HAS_SYS_SELECT_H
#include <sys/select.h>
#endif

static int fdlist_to_fdset(value fdlist, fd_set *fdset, int *maxfd)
{
  value l;
  FD_ZERO(fdset);
  for (l = fdlist; l != Val_int(0); l = Field(l, 1)) {
    long fd = Long_val(Field(l, 0));
    /* PR#5563: harden against bad fds */
    if (fd < 0 || fd >= FD_SETSIZE) return -1;
    FD_SET((int) fd, fdset);
    if (fd > *maxfd) *maxfd = fd;
  }
  return 0;
}

static value fdset_to_fdlist(value fdlist, fd_set *fdset)
{
  value l;
  value res = Val_int(0);

  Begin_roots2(l, res);
    for (l = fdlist; l != Val_int(0); l = Field(l, 1)) {
      int fd = Int_val(Field(l, 0));
      if (FD_ISSET(fd, fdset)) {
        value newres = caml_alloc_small(2, 0);
        Field(newres, 0) = Val_int(fd);
        Field(newres, 1) = res;
        res = newres;
      }
    }
  End_roots();
  return res;
}

CAMLprim value unix_select(value readfds, value writefds, value exceptfds,
                           value timeout)
{
  fd_set read, write, except;
  int maxfd;
  double tm;
  struct timeval tv;
  struct timeval * tvp;
  int retcode;
  value res;

  Begin_roots3 (readfds, writefds, exceptfds);
    maxfd = -1;
    retcode  = fdlist_to_fdset(readfds, &read, &maxfd);
    retcode += fdlist_to_fdset(writefds, &write, &maxfd);
    retcode += fdlist_to_fdset(exceptfds, &except, &maxfd);
    /* PR#5563: if a bad fd was encountered, report EINVAL error */
    if (retcode != 0) unix_error(EINVAL, "select", Nothing);
    tm = Double_val(timeout);
    if (tm < 0.0)
      tvp = (struct timeval *) NULL;
    else {
      tv.tv_sec = (int) tm;
      tv.tv_usec = (int) (1e6 * (tm - tv.tv_sec));
      tvp = &tv;
    }
    caml_enter_blocking_section();
    retcode = select(maxfd + 1, &read, &write, &except, tvp);
    caml_leave_blocking_section();
    if (retcode == -1) uerror("select", Nothing);
    readfds = fdset_to_fdlist(readfds, &read);
    writefds = fdset_to_fdlist(writefds, &write);
    exceptfds = fdset_to_fdlist(exceptfds, &except);
    res = caml_alloc_small(3, 0);
    Field(res, 0) = readfds;
    Field(res, 1) = writefds;
    Field(res, 2) = exceptfds;
  End_roots();
  return res;
}

#else

CAMLprim value unix_select(value readfds, value writefds, value exceptfds,
                           value timeout)
{ caml_invalid_argument("select not implemented"); }

#endif

#ifdef HAS_SOCKETS
#include "socketaddr.h"

static int msg_flag_table[] = {
  MSG_OOB, MSG_DONTROUTE, MSG_PEEK
};

CAMLprim value unix_recv(value sock, value buff, value ofs, value len,
                         value flags)
{
  int ret, cv_flags;
  long numbytes;
  char iobuf[UNIX_BUFFER_SIZE];

  cv_flags = caml_convert_flag_list(flags, msg_flag_table);
  Begin_root (buff);
    numbytes = Long_val(len);
    if (numbytes > UNIX_BUFFER_SIZE) numbytes = UNIX_BUFFER_SIZE;
    caml_enter_blocking_section();
    ret = recv(Int_val(sock), iobuf, (int) numbytes, cv_flags);
    caml_leave_blocking_section();
    if (ret == -1) uerror("recv", Nothing);
    memmove (&Byte(buff, Long_val(ofs)), iobuf, ret);
  End_roots();
  return Val_int(ret);
}

CAMLprim value unix_recvfrom(value sock, value buff, value ofs, value len,
                             value flags)
{
  int ret, cv_flags;
  long numbytes;
  char iobuf[UNIX_BUFFER_SIZE];
  value res;
  value adr = Val_unit;
  union sock_addr_union addr;
  socklen_param_type addr_len;

  cv_flags = caml_convert_flag_list(flags, msg_flag_table);
  Begin_roots2 (buff, adr);
    numbytes = Long_val(len);
    if (numbytes > UNIX_BUFFER_SIZE) numbytes = UNIX_BUFFER_SIZE;
    addr_len = sizeof(addr);
    caml_enter_blocking_section();
    ret = recvfrom(Int_val(sock), iobuf, (int) numbytes, cv_flags,
                   &addr.s_gen, &addr_len);
    caml_leave_blocking_section();
    if (ret == -1) uerror("recvfrom", Nothing);
    memmove (&Byte(buff, Long_val(ofs)), iobuf, ret);
    adr = alloc_sockaddr(&addr, addr_len, -1);
    res = caml_alloc_small(2, 0);
    Field(res, 0) = Val_int(ret);
    Field(res, 1) = adr;
  End_roots();
  return res;
}

CAMLprim value unix_send(value sock, value buff, value ofs, value len,
                         value flags)
{
  int ret, cv_flags;
  long numbytes;
  char iobuf[UNIX_BUFFER_SIZE];

  cv_flags = caml_convert_flag_list(flags, msg_flag_table);
  numbytes = Long_val(len);
  if (numbytes > UNIX_BUFFER_SIZE) numbytes = UNIX_BUFFER_SIZE;
  memmove (iobuf, &Byte(buff, Long_val(ofs)), numbytes);
  caml_enter_blocking_section();
  ret = send(Int_val(sock), iobuf, (int) numbytes, cv_flags);
  caml_leave_blocking_section();
  if (ret == -1) uerror("send", Nothing);
  return Val_int(ret);
}

CAMLprim value unix_sendto_native(value sock, value buff, value ofs, value len,
                                  value flags, value dest)
{
  int ret, cv_flags;
  long numbytes;
  char iobuf[UNIX_BUFFER_SIZE];
  union sock_addr_union addr;
  socklen_param_type addr_len;

  cv_flags = caml_convert_flag_list(flags, msg_flag_table);
  get_sockaddr(dest, &addr, &addr_len);
  numbytes = Long_val(len);
  if (numbytes > UNIX_BUFFER_SIZE) numbytes = UNIX_BUFFER_SIZE;
  memmove (iobuf, &Byte(buff, Long_val(ofs)), numbytes);
  caml_enter_blocking_section();
  ret = sendto(Int_val(sock), iobuf, (int) numbytes, cv_flags,
               &addr.s_gen, addr_len);
  caml_leave_blocking_section();
  if (ret == -1) uerror("sendto", Nothing);
  return Val_int(ret);
}

CAMLprim value unix_sendto(value *argv, int argc)
{
  return unix_sendto_native
           (argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
}

#else

CAMLprim value unix_recv(value sock, value buff, value ofs, value len,
                         value flags)
{ caml_invalid_argument("recv not implemented"); }

CAMLprim value unix_recvfrom(value sock, value buff, value ofs, value len,
                             value flags)
{ caml_invalid_argument("recvfrom not implemented"); }

CAMLprim value unix_send(value sock, value buff, value ofs, value len,
                         value flags)
{ caml_invalid_argument("send not implemented"); }

CAMLprim value unix_sendto_native(value sock, value buff, value ofs, value len,
                                  value flags, value dest)
{ caml_invalid_argument("sendto not implemented"); }

CAMLprim value unix_sendto(value *argv, int argc)
{ caml_invalid_argument("sendto not implemented"); }

#endif

CAMLprim value unix_setgid(value gid)
{
  if (setgid(Int_val(gid)) == -1) uerror("setgid", Nothing);
  return Val_unit;
}

#ifdef HAS_SETGROUPS

#include <sys/types.h>
#ifdef HAS_UNISTD
#include <unistd.h>
#endif
#include <limits.h>
#include <grp.h>
#include "unixsupport.h"

CAMLprim value unix_setgroups(value groups)
{
  gid_t * gidset;
  mlsize_t size, i;
  int n;

  size = Wosize_val(groups);
  gidset = (gid_t *) caml_stat_alloc(size * sizeof(gid_t));
  for (i = 0; i < size; i++) gidset[i] = Int_val(Field(groups, i));

  n = setgroups(size, gidset);

  caml_stat_free(gidset);
  if (n == -1) uerror("setgroups", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_setgroups(value groups)
{ caml_invalid_argument("setgroups not implemented"); }

#endif

CAMLprim value unix_setsid(value unit)
{
#ifdef HAS_SETSID
  pid_t pid = setsid();
  if (pid == (pid_t)(-1)) uerror("setsid", Nothing);
  return Val_long(pid);
#else
  caml_invalid_argument("setsid not implemented");
  return Val_unit;
#endif
}

CAMLprim value unix_setuid(value uid)
{
  if (setuid(Int_val(uid)) == -1) uerror("setuid", Nothing);
  return Val_unit;
}

#ifdef HAS_SOCKETS

#include <sys/socket.h>

static int shutdown_command_table[] = {
  0, 1, 2
};

CAMLprim value unix_shutdown(value sock, value cmd)
{
  if (shutdown(Int_val(sock), shutdown_command_table[Int_val(cmd)]) == -1)
    uerror("shutdown", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_shutdown(value sock, value cmd)
{ caml_invalid_argument("shutdown not implemented"); }

#endif

CAMLprim value unix_sigprocmask(value vaction, value vset)
{ caml_invalid_argument("Unix.sigprocmask not available"); }

CAMLprim value unix_sigpending(value unit)
{ caml_invalid_argument("Unix.sigpending not available"); }

CAMLprim value unix_sigsuspend(value vset)
{ caml_invalid_argument("Unix.sigsuspend not available"); }

CAMLprim value unix_sleep(value duration)
{
  double d = Double_val(duration);
  if (d < 0.0) return Val_unit;
#if defined(HAS_NANOSLEEP)
  {
    struct timespec t;
    int ret;
    t.tv_sec = (time_t) d;
    t.tv_nsec = (d - t.tv_sec) * 1e9;
    do {
      caml_enter_blocking_section();
      ret = nanosleep(&t, &t);
      /* MPR#7903: if we were interrupted by a signal, and this signal
         is handled in OCaml, we should run its handler now,
         not at the end of the full sleep duration.  Leaving the blocking
         section and re-entering it does the job. */
      caml_leave_blocking_section();
    } while (ret == -1 && errno == EINTR);
    if (ret == -1) uerror("sleep", Nothing);
  }
#elif defined(HAS_SELECT)
  {
    struct timeval t;
    int ret;
    t.tv_sec = (time_t) d;
    t.tv_usec = (d - t.tv_sec) * 1e6;
    do {
      caml_enter_blocking_section();
      ret = select(0, NULL, NULL, NULL, &t);
      /* MPR#7903: same comment as above */
      caml_leave_blocking_section();
    } while (ret == -1 && errno == EINTR);
    if (ret == -1) uerror("sleep", Nothing);
  }
#else
  /* Fallback implementation, resolution 1 second only.
     We cannot reliably iterate until sleep() returns 0, because the
     remaining time returned by sleep() is generally rounded up. */
  {
    caml_enter_blocking_section();
    sleep ((unsigned int) d);
    caml_leave_blocking_section();
  }
#endif
  return Val_unit;
}

#ifdef HAS_SOCKETS

CAMLprim value unix_socket(value cloexec, value domain,
                           value type, value proto)
{
  int retcode;
  int ty = socket_type_table[Int_val(type)];
#ifdef SOCK_CLOEXEC
  if (unix_cloexec_p(cloexec)) ty |= SOCK_CLOEXEC;
#endif
  retcode = socket(socket_domain_table[Int_val(domain)],
                   ty, Int_val(proto));
  if (retcode == -1) uerror("socket", Nothing);
#ifndef SOCK_CLOEXEC
  if (unix_cloexec_p(cloexec))
    unix_set_cloexec(retcode, "socket", Nothing);
#endif
  return Val_int(retcode);
}

#else

CAMLprim value unix_socket(value cloexec, value domain,
                           value type,value proto)
{ caml_invalid_argument("socket not implemented"); }

#endif

#ifdef HAS_SOCKETS

CAMLprim value unix_socketpair(value cloexec, value domain,
                               value type, value proto)
{
  int sv[2];
  value res;
  int ty = socket_type_table[Int_val(type)];
#ifdef SOCK_CLOEXEC
  if (unix_cloexec_p(cloexec)) ty |= SOCK_CLOEXEC;
#endif
  if (socketpair(socket_domain_table[Int_val(domain)],
                 ty, Int_val(proto), sv) == -1)
    uerror("socketpair", Nothing);
#ifndef SOCK_CLOEXEC
  if (unix_cloexec_p(cloexec)) {
    unix_set_cloexec(sv[0], "socketpair", Nothing);
    unix_set_cloexec(sv[1], "socketpair", Nothing);
  }
#endif
  res = caml_alloc_small(2, 0);
  Field(res,0) = Val_int(sv[0]);
  Field(res,1) = Val_int(sv[1]);
  return res;
}

#else

CAMLprim value unix_socketpair(value domain, value type, value proto)
{ caml_invalid_argument("socketpair not implemented"); }

#endif

#ifdef HAS_SOCKETS

#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "socketaddr.h"

#ifndef SO_DEBUG
#define SO_DEBUG (-1)
#endif
#ifndef SO_BROADCAST
#define SO_BROADCAST (-1)
#endif
#ifndef SO_REUSEADDR
#define SO_REUSEADDR (-1)
#endif
#ifndef SO_REUSEPORT
#define SO_REUSEPORT (-1)
#endif
#ifndef SO_KEEPALIVE
#define SO_KEEPALIVE (-1)
#endif
#ifndef SO_DONTROUTE
#define SO_DONTROUTE (-1)
#endif
#ifndef SO_OOBINLINE
#define SO_OOBINLINE (-1)
#endif
#ifndef SO_ACCEPTCONN
#define SO_ACCEPTCONN (-1)
#endif
#ifndef SO_SNDBUF
#define SO_SNDBUF (-1)
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF (-1)
#endif
#ifndef SO_ERROR
#define SO_ERROR (-1)
#endif
#ifndef SO_TYPE
#define SO_TYPE (-1)
#endif
#ifndef SO_RCVLOWAT
#define SO_RCVLOWAT (-1)
#endif
#ifndef SO_SNDLOWAT
#define SO_SNDLOWAT (-1)
#endif
#ifndef SO_LINGER
#define SO_LINGER (-1)
#endif
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO (-1)
#endif
#ifndef SO_SNDTIMEO
#define SO_SNDTIMEO (-1)
#endif
#ifndef TCP_NODELAY
#define TCP_NODELAY (-1)
#endif
#ifndef SO_ERROR
#define SO_ERROR (-1)
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 (-1)
#endif
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY (-1)
#endif

enum option_type {
  TYPE_BOOL = 0,
  TYPE_INT = 1,
  TYPE_LINGER = 2,
  TYPE_TIMEVAL = 3,
  TYPE_UNIX_ERROR = 4
};

struct socket_option {
  int level;
  int option;
};

/* Table of options, indexed by type */

static struct socket_option sockopt_bool[] = {
  { SOL_SOCKET, SO_DEBUG },
  { SOL_SOCKET, SO_BROADCAST },
  { SOL_SOCKET, SO_REUSEADDR },
  { SOL_SOCKET, SO_KEEPALIVE },
  { SOL_SOCKET, SO_DONTROUTE },
  { SOL_SOCKET, SO_OOBINLINE },
  { SOL_SOCKET, SO_ACCEPTCONN },
  { IPPROTO_TCP, TCP_NODELAY },
  { IPPROTO_IPV6, IPV6_V6ONLY},
  { SOL_SOCKET, SO_REUSEPORT }
};

static struct socket_option sockopt_int[] = {
  { SOL_SOCKET, SO_SNDBUF },
  { SOL_SOCKET, SO_RCVBUF },
  { SOL_SOCKET, SO_ERROR },
  { SOL_SOCKET, SO_TYPE },
  { SOL_SOCKET, SO_RCVLOWAT },
  { SOL_SOCKET, SO_SNDLOWAT } };

static struct socket_option sockopt_linger[] = {
  { SOL_SOCKET, SO_LINGER }
};

static struct socket_option sockopt_timeval[] = {
  { SOL_SOCKET, SO_RCVTIMEO },
  { SOL_SOCKET, SO_SNDTIMEO }
};

static struct socket_option sockopt_unix_error[] = {
  { SOL_SOCKET, SO_ERROR }
};

static struct socket_option * sockopt_table[] = {
  sockopt_bool,
  sockopt_int,
  sockopt_linger,
  sockopt_timeval,
  sockopt_unix_error
};

static char * getsockopt_fun_name[] = {
  "getsockopt",
  "getsockopt_int",
  "getsockopt_optint",
  "getsockopt_float",
  "getsockopt_error"
};

static char * setsockopt_fun_name[] = {
  "setsockopt",
  "setsockopt_int",
  "setsockopt_optint",
  "setsockopt_float",
  "setsockopt_error"
};

union option_value {
  int i;
  struct linger lg;
  struct timeval tv;
};

CAMLexport value
unix_getsockopt_aux(char * name,
                    enum option_type ty, int level, int option,
                    value socket)
{
  union option_value optval;
  socklen_param_type optsize;


  switch (ty) {
  case TYPE_BOOL:
  case TYPE_INT:
  case TYPE_UNIX_ERROR:
    optsize = sizeof(optval.i); break;
  case TYPE_LINGER:
    optsize = sizeof(optval.lg); break;
  case TYPE_TIMEVAL:
    optsize = sizeof(optval.tv); break;
  default:
    unix_error(EINVAL, name, Nothing);
  }

  if (getsockopt(Int_val(socket), level, option,
                 (void *) &optval, &optsize) == -1)
    uerror(name, Nothing);

  switch (ty) {
  case TYPE_BOOL:
    return Val_bool(optval.i);
  case TYPE_INT:
    return Val_int(optval.i);
  case TYPE_LINGER:
    if (optval.lg.l_onoff == 0) {
      return Val_int(0);        /* None */
    } else {
      value res = caml_alloc_small(1, 0); /* Some */
      Field(res, 0) = Val_int(optval.lg.l_linger);
      return res;
    }
  case TYPE_TIMEVAL:
    return caml_copy_double((double) optval.tv.tv_sec
                       + (double) optval.tv.tv_usec / 1e6);
  case TYPE_UNIX_ERROR:
    if (optval.i == 0) {
      return Val_int(0);        /* None */
    } else {
      value err, res;
      err = unix_error_of_code(optval.i);
      Begin_root(err);
        res = caml_alloc_small(1, 0); /* Some */
        Field(res, 0) = err;
      End_roots();
      return res;
    }
  default:
    unix_error(EINVAL, name, Nothing);
  }
}

CAMLexport value
unix_setsockopt_aux(char * name,
                    enum option_type ty, int level, int option,
                    value socket, value val)
{
  union option_value optval;
  socklen_param_type optsize;
  double f;

  switch (ty) {
  case TYPE_BOOL:
  case TYPE_INT:
    optsize = sizeof(optval.i);
    optval.i = Int_val(val);
    break;
  case TYPE_LINGER:
    optsize = sizeof(optval.lg);
    optval.lg.l_onoff = Is_block (val);
    if (optval.lg.l_onoff)
      optval.lg.l_linger = Int_val (Field (val, 0));
    break;
  case TYPE_TIMEVAL:
    f = Double_val(val);
    optsize = sizeof(optval.tv);
    optval.tv.tv_sec = (int) f;
    optval.tv.tv_usec = (int) (1e6 * (f - optval.tv.tv_sec));
    break;
  case TYPE_UNIX_ERROR:
  default:
    unix_error(EINVAL, name, Nothing);
  }

  if (setsockopt(Int_val(socket), level, option,
                 (void *) &optval, optsize) == -1)
    uerror(name, Nothing);

  return Val_unit;
}

CAMLprim value unix_getsockopt(value vty, value vsocket, value voption)
{
  enum option_type ty = Int_val(vty);
  struct socket_option * opt = &(sockopt_table[ty][Int_val(voption)]);
  return unix_getsockopt_aux(getsockopt_fun_name[ty],
                             ty,
                             opt->level,
                             opt->option,
                             vsocket);
}

CAMLprim value unix_setsockopt(value vty, value vsocket, value voption,
                               value val)
{
  enum option_type ty = Int_val(vty);
  struct socket_option * opt = &(sockopt_table[ty][Int_val(voption)]);
  return unix_setsockopt_aux(setsockopt_fun_name[ty],
                             ty,
                             opt->level,
                             opt->option,
                             vsocket,
                             val);
}

#else

CAMLprim value unix_getsockopt(value vty, value socket, value option)
{ caml_invalid_argument("getsockopt not implemented"); }

CAMLprim value unix_setsockopt(value vty, value socket, value option, value val)
{ caml_invalid_argument("setsockopt not implemented"); }

#endif

CAMLprim value unix_spawn(value executable, /* string */
                          value args,       /* string array */
                          value optenv,     /* string array option */
                          value usepath,    /* bool */
                          value redirect)   /* int array (size 3) */
{
  caml_invalid_argument("spawn not implemented");
}

#ifndef S_IFLNK
#define S_IFLNK 0
#endif
#ifndef S_IFIFO
#define S_IFIFO 0
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0
#endif
#ifndef S_IFBLK
#define S_IFBLK 0
#endif

#ifndef EOVERFLOW
#define EOVERFLOW ERANGE
#endif

static int file_kind_table[] = {
  S_IFREG, S_IFDIR, S_IFCHR, S_IFBLK, S_IFLNK, S_IFIFO, S_IFSOCK
};

/* Transform a (seconds, nanoseconds) time stamp (in the style of
   struct timespec) to a number of seconds in floating-point.
   Make sure the integer part of the result is always equal to [seconds]
   (issue #9490). */

static double stat_timestamp(time_t sec, long nsec)
{
  /* The conversion of sec to FP is exact for the foreseeable future.
     (It starts rounding when sec > 2^53, i.e. in 285 million years.) */
  double s = (double) sec;
  /* The conversion of nsec to fraction of seconds can round.
     Still, we have 0 <= n < 1.0. */
  double n = (double) nsec / 1e9;
  /* The sum s + n can round up, hence s <= t + <= s + 1.0 */
  double t = s + n;
  /* Detect the "round up to s + 1" case and decrease t so that
     its integer part is s. */
  if (t == s + 1.0) t = nextafter(t, s);
  return t;
}

static value stat_aux(int use_64, struct stat *buf)
{
  CAMLparam0();
  CAMLlocal5(atime, mtime, ctime, offset, v);

  #include "nanosecond_stat.h"
  atime = caml_copy_double(stat_timestamp(buf->st_atime, NSEC(buf, a)));
  mtime = caml_copy_double(stat_timestamp(buf->st_mtime, NSEC(buf, m)));
  ctime = caml_copy_double(stat_timestamp(buf->st_ctime, NSEC(buf, c)));
  #undef NSEC
  offset = use_64 ? Val_file_offset(buf->st_size) : Val_int (buf->st_size);
  v = caml_alloc_small(12, 0);
  Field (v, 0) = Val_int (buf->st_dev);
  Field (v, 1) = Val_int (buf->st_ino);
  Field (v, 2) = cst_to_constr(buf->st_mode & S_IFMT, file_kind_table,
                               sizeof(file_kind_table) / sizeof(int), 0);
  Field (v, 3) = Val_int (buf->st_mode & 07777);
  Field (v, 4) = Val_int (buf->st_nlink);
  Field (v, 5) = Val_int (buf->st_uid);
  Field (v, 6) = Val_int (buf->st_gid);
  Field (v, 7) = Val_int (buf->st_rdev);
  Field (v, 8) = offset;
  Field (v, 9) = atime;
  Field (v, 10) = mtime;
  Field (v, 11) = ctime;
  CAMLreturn(v);
}

CAMLprim value unix_stat(value path)
{
  CAMLparam1(path);
  int ret;
  struct stat buf;
  char * p;
  caml_unix_check_path(path, "stat");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = stat(p, &buf);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("stat", path);
  if (buf.st_size > Max_long && (buf.st_mode & S_IFMT) == S_IFREG)
    unix_error(EOVERFLOW, "stat", path);
  CAMLreturn(stat_aux(0, &buf));
}

CAMLprim value unix_lstat(value path)
{
  CAMLparam1(path);
  int ret;
  struct stat buf;
  char * p;
  caml_unix_check_path(path, "lstat");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
#ifdef HAS_SYMLINK
  ret = lstat(p, &buf);
#else
  ret = stat(p, &buf);
#endif
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("lstat", path);
  if (buf.st_size > Max_long && (buf.st_mode & S_IFMT) == S_IFREG)
    unix_error(EOVERFLOW, "lstat", path);
  CAMLreturn(stat_aux(0, &buf));
}

CAMLprim value unix_fstat(value fd)
{
  int ret;
  struct stat buf;
  caml_enter_blocking_section();
  ret = fstat(Int_val(fd), &buf);
  caml_leave_blocking_section();
  if (ret == -1) uerror("fstat", Nothing);
  if (buf.st_size > Max_long && (buf.st_mode & S_IFMT) == S_IFREG)
    unix_error(EOVERFLOW, "fstat", Nothing);
  return stat_aux(0, &buf);
}

CAMLprim value unix_stat_64(value path)
{
  CAMLparam1(path);
  int ret;
  struct stat buf;
  char * p;
  caml_unix_check_path(path, "stat");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = stat(p, &buf);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("stat", path);
  CAMLreturn(stat_aux(1, &buf));
}

CAMLprim value unix_lstat_64(value path)
{
  CAMLparam1(path);
  int ret;
  struct stat buf;
  char * p;
  caml_unix_check_path(path, "lstat");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
#ifdef HAS_SYMLINK
  ret = lstat(p, &buf);
#else
  ret = stat(p, &buf);
#endif
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("lstat", path);
  CAMLreturn(stat_aux(1, &buf));
}

CAMLprim value unix_fstat_64(value fd)
{
  int ret;
  struct stat buf;
  caml_enter_blocking_section();
  ret = fstat(Int_val(fd), &buf);
  caml_leave_blocking_section();
  if (ret == -1) uerror("fstat", Nothing);
  return stat_aux(1, &buf);
}

#ifdef HAS_SOCKETS

#include "socketaddr.h"

CAMLprim value unix_string_of_inet_addr(value a)
{
  char * res;
#ifdef HAS_IPV6
#ifdef _WIN32
  char buffer[64];
  union sock_addr_union sa;
  int len;
  int retcode;
  if (caml_string_length(a) == 16) {
    memset(&sa.s_inet6, 0, sizeof(struct sockaddr_in6));
    sa.s_inet6.sin6_family = AF_INET6;
    sa.s_inet6.sin6_addr = GET_INET6_ADDR(a);
    len = sizeof(struct sockaddr_in6);
  } else {
    memset(&sa.s_inet, 0, sizeof(struct sockaddr_in));
    sa.s_inet.sin_family = AF_INET;
    sa.s_inet.sin_addr = GET_INET_ADDR(a);
    len = sizeof(struct sockaddr_in);
  }
  retcode = getnameinfo
    (&sa.s_gen, len, buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST);
  if (retcode != 0)
    res = NULL;
  else
    res = buffer;
#else
  char buffer[64];
  if (caml_string_length(a) == 16)
    res = (char *)
      inet_ntop(AF_INET6, (const void *) &GET_INET6_ADDR(a),
                buffer, sizeof(buffer));
  else
    res = (char *)
      inet_ntop(AF_INET, (const void *) &GET_INET_ADDR(a),
                buffer, sizeof(buffer));
#endif
#else
  res = inet_ntoa(GET_INET_ADDR(a));
#endif
  if (res == NULL) uerror("string_of_inet_addr", Nothing);
  return caml_copy_string(res);
}

#else

CAMLprim value unix_string_of_inet_addr(value a)
{ caml_invalid_argument("string_of_inet_addr not implemented"); }

#endif

#ifdef HAS_SYMLINK

CAMLprim value unix_symlink(value to_dir, value path1, value path2)
{
  CAMLparam3(to_dir, path1, path2);
  char * p1;
  char * p2;
  int ret;
  caml_unix_check_path(path1, "symlink");
  caml_unix_check_path(path2, "symlink");
  p1 = caml_stat_strdup(String_val(path1));
  p2 = caml_stat_strdup(String_val(path2));
  caml_enter_blocking_section();
  ret = symlink(p1, p2);
  caml_leave_blocking_section();
  caml_stat_free(p1);
  caml_stat_free(p2);
  if (ret == -1)
    uerror("symlink", path2);
  CAMLreturn(Val_unit);
}

CAMLprim value unix_has_symlink(value unit)
{
  CAMLparam0();
  CAMLreturn(Val_true);
}

#else

CAMLprim value unix_symlink(value to_dir, value path1, value path2)
{ caml_invalid_argument("symlink not implemented"); }

CAMLprim value unix_has_symlink(value unit)
{
  CAMLparam0();
  CAMLreturn(Val_false);
}

#endif

#ifdef HAS_TERMIOS

#include <termios.h>
#include <errno.h>

static struct termios terminal_status;

enum { Bool, Enum, Speed, Char, End };

enum { Input, Output };

#define iflags ((long)(&terminal_status.c_iflag))
#define oflags ((long)(&terminal_status.c_oflag))
#define cflags ((long)(&terminal_status.c_cflag))
#define lflags ((long)(&terminal_status.c_lflag))

/* Number of fields in the terminal_io record field. Cf. unix.mli */

#define NFIELDS 38

/* Structure of the terminal_io record. Cf. unix.mli */

static long terminal_io_descr[] = {
  /* Input modes */
  Bool, iflags, IGNBRK,
  Bool, iflags, BRKINT,
  Bool, iflags, IGNPAR,
  Bool, iflags, PARMRK,
  Bool, iflags, INPCK,
  Bool, iflags, ISTRIP,
  Bool, iflags, INLCR,
  Bool, iflags, IGNCR,
  Bool, iflags, ICRNL,
  Bool, iflags, IXON,
  Bool, iflags, IXOFF,
  /* Output modes */
  Bool, oflags, OPOST,
  /* Control modes */
  Speed, Output,
  Speed, Input,
  Enum, cflags, 5, 4, CSIZE, CS5, CS6, CS7, CS8,
  Enum, cflags, 1, 2, CSTOPB, 0, CSTOPB,
  Bool, cflags, CREAD,
  Bool, cflags, PARENB,
  Bool, cflags, PARODD,
  Bool, cflags, HUPCL,
  Bool, cflags, CLOCAL,
  /* Local modes */
  Bool, lflags, ISIG,
  Bool, lflags, ICANON,
  Bool, lflags, NOFLSH,
  Bool, lflags, ECHO,
  Bool, lflags, ECHOE,
  Bool, lflags, ECHOK,
  Bool, lflags, ECHONL,
  /* Control characters */
  Char, VINTR,
  Char, VQUIT,
  Char, VERASE,
  Char, VKILL,
  Char, VEOF,
  Char, VEOL,
  Char, VMIN,
  Char, VTIME,
  Char, VSTART,
  Char, VSTOP,
  End
};

#undef iflags
#undef oflags
#undef cflags
#undef lflags

static struct {
  speed_t speed;
  int baud;
} speedtable[] = {

  /* standard speeds */
  {B0,       0},
  {B50,      50},
  {B75,      75},
  {B110,     110},
  {B134,     134},
  {B150,     150},
#ifdef B200
  /* Shouldn't need to be ifdef'd but I'm not sure it's available everywhere. */
  {B200,     200},
#endif
  {B300,     300},
  {B600,     600},
  {B1200,    1200},
  {B1800,    1800},
  {B2400,    2400},
  {B4800,    4800},
  {B9600,    9600},
  {B19200,   19200},
  {B38400,   38400},

  /* usual extensions */
#ifdef B57600
  {B57600,   57600},
#endif
#ifdef B115200
  {B115200,  115200},
#endif
#ifdef B230400
  {B230400,  230400},
#endif

  /* Linux extensions */
#ifdef B460800
  {B460800,  460800},
#endif
#ifdef B500000
  {B500000,  500000},
#endif
#ifdef B576000
  {B576000,  576000},
#endif
#ifdef B921600
  {B921600,  921600},
#endif
#ifdef B1000000
  {B1000000, 1000000},
#endif
#ifdef B1152000
  {B1152000, 1152000},
#endif
#ifdef B1500000
  {B1500000, 1500000},
#endif
#ifdef B2000000
  {B2000000, 2000000},
#endif
#ifdef B2500000
  {B2500000, 2500000},
#endif
#ifdef B3000000
  {B3000000, 3000000},
#endif
#ifdef B3500000
  {B3500000, 3500000},
#endif
#ifdef B4000000
  {B4000000, 4000000},
#endif

  /* MacOS extensions */
#ifdef B7200
  {B7200,    7200},
#endif
#ifdef B14400
  {B14400,   14400},
#endif
#ifdef B28800
  {B28800,   28800},
#endif
#ifdef B76800
  {B76800,   76800},
#endif

  /* Cygwin extensions (in addition to the Linux ones) */
#ifdef B128000
  {B128000,  128000},
#endif
#ifdef B256000
  {B256000,  256000},
#endif
};

#define NSPEEDS (sizeof(speedtable) / sizeof(speedtable[0]))

static void encode_terminal_status(value *dst)
{
  long * pc;
  int i;

  for(pc = terminal_io_descr; *pc != End; dst++) {
    switch(*pc++) {
    case Bool:
      { int * src = (int *) (*pc++);
        int msk = *pc++;
        *dst = Val_bool(*src & msk);
        break; }
    case Enum:
      { int * src = (int *) (*pc++);
        int ofs = *pc++;
        int num = *pc++;
        int msk = *pc++;
        for (i = 0; i < num; i++) {
          if ((*src & msk) == pc[i]) {
            *dst = Val_int(i + ofs);
            break;
          }
        }
        pc += num;
        break; }
    case Speed:
      { int which = *pc++;
        speed_t speed = 0;
        *dst = Val_int(9600);   /* in case no speed in speedtable matches */
        switch (which) {
        case Output:
          speed = cfgetospeed(&terminal_status); break;
        case Input:
          speed = cfgetispeed(&terminal_status); break;
        }
        for (i = 0; i < NSPEEDS; i++) {
          if (speed == speedtable[i].speed) {
            *dst = Val_int(speedtable[i].baud);
            break;
          }
        }
        break; }
    case Char:
      { int which = *pc++;
        *dst = Val_int(terminal_status.c_cc[which]);
        break; }
    }
  }
}

static void decode_terminal_status(value *src)
{
  long * pc;
  int i;

  for (pc = terminal_io_descr; *pc != End; src++) {
    switch(*pc++) {
    case Bool:
      { int * dst = (int *) (*pc++);
        int msk = *pc++;
        if (Bool_val(*src))
          *dst |= msk;
        else
          *dst &= ~msk;
        break; }
    case Enum:
      { int * dst = (int *) (*pc++);
        int ofs = *pc++;
        int num = *pc++;
        int msk = *pc++;
        i = Int_val(*src) - ofs;
        if (i >= 0 && i < num) {
          *dst = (*dst & ~msk) | pc[i];
        } else {
          unix_error(EINVAL, "tcsetattr", Nothing);
        }
        pc += num;
        break; }
    case Speed:
      { int which = *pc++;
        int baud = Int_val(*src);
        int res = 0;
        for (i = 0; i < NSPEEDS; i++) {
          if (baud == speedtable[i].baud) {
            switch (which) {
            case Output:
              res = cfsetospeed(&terminal_status, speedtable[i].speed); break;
            case Input:
              res = cfsetispeed(&terminal_status, speedtable[i].speed); break;
            }
            if (res == -1) uerror("tcsetattr", Nothing);
            goto ok;
          }
        }
        unix_error(EINVAL, "tcsetattr", Nothing);
      ok:
        break; }
    case Char:
      { int which = *pc++;
        terminal_status.c_cc[which] = Int_val(*src);
        break; }
    }
  }
}

CAMLprim value unix_tcgetattr(value fd)
{
  value res;

  if (tcgetattr(Int_val(fd), &terminal_status) == -1)
    uerror("tcgetattr", Nothing);
  res = caml_alloc_tuple(NFIELDS);
  encode_terminal_status(&Field(res, 0));
  return res;
}

static int when_flag_table[] = {
  TCSANOW, TCSADRAIN, TCSAFLUSH
};

CAMLprim value unix_tcsetattr(value fd, value when, value arg)
{
  if (tcgetattr(Int_val(fd), &terminal_status) == -1)
    uerror("tcsetattr", Nothing);
  decode_terminal_status(&Field(arg, 0));
  if (tcsetattr(Int_val(fd),
                when_flag_table[Int_val(when)],
                &terminal_status) == -1)
    uerror("tcsetattr", Nothing);
  return Val_unit;
}

CAMLprim value unix_tcsendbreak(value fd, value delay)
{
  if (tcsendbreak(Int_val(fd), Int_val(delay)) == -1)
    uerror("tcsendbreak", Nothing);
  return Val_unit;
}

#if defined(__ANDROID__)
CAMLprim value unix_tcdrain(value fd)
{ caml_invalid_argument("tcdrain not implemented"); }
#else
CAMLprim value unix_tcdrain(value fd)
{
  if (tcdrain(Int_val(fd)) == -1) uerror("tcdrain", Nothing);
  return Val_unit;
}
#endif

static int queue_flag_table[] = {
  TCIFLUSH, TCOFLUSH, TCIOFLUSH
};

CAMLprim value unix_tcflush(value fd, value queue)
{
  if (tcflush(Int_val(fd), queue_flag_table[Int_val(queue)]) == -1)
    uerror("tcflush", Nothing);
  return Val_unit;
}

static int action_flag_table[] = {
  TCOOFF, TCOON, TCIOFF, TCION
};

CAMLprim value unix_tcflow(value fd, value action)
{
  if (tcflow(Int_val(fd), action_flag_table[Int_val(action)]) == -1)
    uerror("tcflow", Nothing);
  return Val_unit;
}

#else

CAMLprim value unix_tcgetattr(value fd)
{ caml_invalid_argument("tcgetattr not implemented"); }

CAMLprim value unix_tcsetattr(value fd, value when, value arg)
{ caml_invalid_argument("tcsetattr not implemented"); }

CAMLprim value unix_tcsendbreak(value fd, value delay)
{ caml_invalid_argument("tcsendbreak not implemented"); }

CAMLprim value unix_tcdrain(value fd)
{ caml_invalid_argument("tcdrain not implemented"); }

CAMLprim value unix_tcflush(value fd, value queue)
{ caml_invalid_argument("tcflush not implemented"); }

CAMLprim value unix_tcflow(value fd, value action)
{ caml_invalid_argument("tcflow not implemented"); }

#endif

double unix_time_unboxed(value unit)
{
  return ((double) time((time_t *) NULL));
}

CAMLprim value unix_time(value unit)
{
  return caml_copy_double(unix_time_unboxed(unit));
}

CAMLprim value unix_times(value unit)
{
#ifdef HAS_GETRUSAGE

  value res;
  struct rusage ru;

  res = caml_alloc_small(4 * Double_wosize, Double_array_tag);

  getrusage (RUSAGE_SELF, &ru);
  Store_double_field (res, 0, ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6);
  Store_double_field (res, 1, ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6);
  getrusage (RUSAGE_CHILDREN, &ru);
  Store_double_field (res, 2, ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6);
  Store_double_field (res, 3, ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6);
  return res;

#else

#ifndef CLK_TCK
#ifdef HZ
#define CLK_TCK HZ
#else
#define CLK_TCK 60
#endif
#endif

  value res;
  struct tms buffer;

  times(&buffer);
  res = caml_alloc_small(4 * Double_wosize, Double_array_tag);
  Store_double_field(res, 0, (double) buffer.tms_utime / CLK_TCK);
  Store_double_field(res, 1, (double) buffer.tms_stime / CLK_TCK);
  Store_double_field(res, 2, (double) buffer.tms_cutime / CLK_TCK);
  Store_double_field(res, 3, (double) buffer.tms_cstime / CLK_TCK);
  return res;

#endif
}

#ifdef HAS_TRUNCATE

CAMLprim value unix_truncate(value path, value len)
{
  CAMLparam2(path, len);
  char * p;
  int ret;
  caml_unix_check_path(path, "truncate");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = truncate(p, Long_val(len));
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1)
    uerror("truncate", path);
  CAMLreturn(Val_unit);
}

CAMLprim value unix_truncate_64(value path, value vlen)
{
  CAMLparam2(path, vlen);
  char * p;
  int ret;
  file_offset len = File_offset_val(vlen);
  caml_unix_check_path(path, "truncate");
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = truncate(p, len);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1)
    uerror("truncate", path);
  CAMLreturn(Val_unit);
}

#else

CAMLprim value unix_truncate(value path, value len)
{ caml_invalid_argument("truncate not implemented"); }

CAMLprim value unix_truncate_64(value path, value len)
{ caml_invalid_argument("truncate not implemented"); }

#endif

CAMLprim value unix_umask(value perm)
{
  return Val_int(umask(Int_val(perm)));
}

CAMLprim value unix_unlink(value path)
{
  CAMLparam1(path);
  char_os * p;
  int ret;
  caml_unix_check_path(path, "unlink");
  p = caml_stat_strdup_to_os(String_val(path));
  caml_enter_blocking_section();
  ret = unlink_os(p);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("unlink", path);
  CAMLreturn(Val_unit);
}

#if defined(HAS_UTIMES)

CAMLprim value unix_utimes(value path, value atime, value mtime)
{
  CAMLparam3(path, atime, mtime);
  struct timeval tv[2], * t;
  char * p;
  int ret;
  double at, mt;
  caml_unix_check_path(path, "utimes");
  at = Double_val(atime);
  mt = Double_val(mtime);
  if (at == 0.0 && mt == 0.0) {
    t = (struct timeval *) NULL;
  } else {
    tv[0].tv_sec = at;
    tv[0].tv_usec = (at - tv[0].tv_sec) * 1000000;
    tv[1].tv_sec = mt;
    tv[1].tv_usec = (mt - tv[1].tv_sec) * 1000000;
    t = tv;
  }
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = utimes(p, t);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("utimes", path);
  CAMLreturn(Val_unit);
}

#elif defined(HAS_UTIME)

#include <sys/types.h>
#include <utime.h>

CAMLprim value unix_utimes(value path, value atime, value mtime)
{
  CAMLparam3(path, atime, mtime);
  struct utimbuf times, * t;
  char * p;
  int ret;
  double at, mt;
  caml_unix_check_path(path, "utimes");
  at = Double_val(atime);
  mt = Double_val(mtime);
  if (at == 0.0 && mt == 0.0) {
    t = NULL;
  } else {
    times.actime = at;
    times.modtime = mt;
    t = &times;
  }
  p = caml_stat_strdup(String_val(path));
  caml_enter_blocking_section();
  ret = utime(p, t);
  caml_leave_blocking_section();
  caml_stat_free(p);
  if (ret == -1) uerror("utimes", path);
  CAMLreturn(Val_unit);
}

#else

CAMLprim value unix_utimes(value path, value atime, value mtime)
{ caml_invalid_argument("utimes not implemented"); }

#endif

CAMLprim value unix_wait(value flags, value pid_req)
{ caml_invalid_argument("wait not implemented"); }

CAMLprim value unix_waitpid(value flags, value pid_req)
{ caml_invalid_argument("waitpid not implemented"); }

#ifndef EAGAIN
#define EAGAIN (-1)
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK (-1)
#endif

CAMLprim value unix_write(value fd, value buf, value vofs, value vlen)
{
  long ofs, len, written;
  int numbytes, ret;
  char iobuf[UNIX_BUFFER_SIZE];

  Begin_root (buf);
    ofs = Long_val(vofs);
    len = Long_val(vlen);
    written = 0;
    while (len > 0) {
      numbytes = len > UNIX_BUFFER_SIZE ? UNIX_BUFFER_SIZE : len;
      memmove (iobuf, &Byte(buf, ofs), numbytes);
      caml_enter_blocking_section();
      ret = write(Int_val(fd), iobuf, numbytes);
      caml_leave_blocking_section();
      if (ret == -1) {
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && written > 0) break;
        uerror("write", Nothing);
      }
      written += ret;
      ofs += ret;
      len -= ret;
    }
  End_roots();
  return Val_long(written);
}

/* When an error occurs after the first loop, unix_write reports the
   error and discards the number of already written characters.
   In this case, it would be better to discard the error and return the
   number of bytes written, since most likely, unix_write will be call again,
   and the error will be reproduced and this time will be reported.
   This problem is avoided in unix_single_write, which is faithful to the
   Unix system call. */

CAMLprim value unix_single_write(value fd, value buf, value vofs, value vlen)
{
  long ofs, len;
  int numbytes, ret;
  char iobuf[UNIX_BUFFER_SIZE];

  Begin_root (buf);
    ofs = Long_val(vofs);
    len = Long_val(vlen);
    ret = 0;
    if (len > 0) {
      numbytes = len > UNIX_BUFFER_SIZE ? UNIX_BUFFER_SIZE : len;
      memmove (iobuf, &Byte(buf, ofs), numbytes);
      caml_enter_blocking_section();
      ret = write(Int_val(fd), iobuf, numbytes);
      caml_leave_blocking_section();
      if (ret == -1) uerror("single_write", Nothing);
    }
  End_roots();
  return Val_int(ret);
}
