This is a simple sample-based profiler for Linux/x86(_64) based on
ptrace.  It uses ptrace to attach to its child process and sample each
of its threads (or just its main thread, if you prefer) periodically,
following the frame pointer to generate a stack trace each time.  When
the child exits, the profiler, dumps a text summary of the sampling
results to the file you specify.

Usage:

  profile [-o <output file>] [--main-thread-only] <command> [<argument>...]


Example:

  profile -o profile.txt ffmpeg -i foo.webm -vcodec libx264 /tmp/foo.mp4


Caveat: The profiler uses the frame pointer (EBP/RBP) to generate a
stack trace, which means you must build your code with
-fno-omit-frame-pointer in order to get useful stack traces.  In the
example above, both libx264 and ffmpeg should be built with that
option, and ideally, libc and other libraries they might use.  If
anyone has suggestions for removing this limitation, I'd love to hear
them.
