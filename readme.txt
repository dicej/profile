This is a simple sample-based profiler for Linux/x86(_64) based on
ptrace, libunwind, and elf.h.  It uses ptrace to attach to its child
process and sample each of its threads (or just its main thread, if
you prefer) periodically, using libunwind to generate a stack trace
each time.  When the child exits, the profiler dumps a text summary of
the sampling results to the file you specify.

Usage:

  profile [-o <output file>] [--main-thread-only] <command> [<argument>...]


Example:

  profile -o profile.txt ffmpeg -i foo.webm -vcodec libx264 /tmp/foo.mp4
