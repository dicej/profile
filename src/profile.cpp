#include "sys/reg.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "sys/mman.h"
#include "sys/ptrace.h"
#include "sys/wait.h"
#include "time.h"
#include "fcntl.h"
#include "unistd.h"
#include "dirent.h"
#include "elf.h"
#include "errno.h"
#include "signal.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

inline void* operator new(size_t, void* p) throw() { return p; }

namespace {

#ifdef __x86_64__
const int Instruction = RIP;
const int Base = RBP;
const int ElfClass = ELFCLASS64;
const int ElfArchitecture = EM_X86_64;

typedef Elf64_Sym ElfSymbol;
typedef Elf64_Ehdr ElfFileHeader;
typedef Elf64_Shdr ElfSectionHeader;

int elfType(int v) { return ELF64_ST_TYPE(v); }
#else // i386
const int Instruction = EIP;
const int Base = EBP;
const int ElfClass = ELFCLASS32;
const int ElfArchitecture = EM_386;

typedef Elf32_Sym ElfSymbol;
typedef Elf32_Ehdr ElfFileHeader;
typedef Elf32_Shdr ElfSectionHeader;

int elfType(int v) { return ELF32_ST_TYPE(v); }
#endif

bool done = false;

void
handleSignal(int signal, siginfo_t* info, void*)
{
  //fprintf(stderr, "signal %d\n", signal);

  if (signal == SIGINT
      or info->si_code == CLD_EXITED
      or info->si_code == CLD_KILLED
      or info->si_code == CLD_DUMPED)
  {
    fprintf(stderr, "done\n");
    done = true;
  }
}

const unsigned BytesPerWord = sizeof(void*);

inline unsigned
pad(unsigned n)
{
  return (n + (BytesPerWord - 1)) & ~(BytesPerWord - 1);
}

unsigned
hash(const char* s)
{
  uint32_t h = 0;
  for (unsigned i = 0; s[i]; ++i) {
    h = (h * 31) + s[i];
  }
  return h;
}

class Set {
 public:
  class Entry {
   public:
    void* value;
    unsigned hash;
    int next;
  };

  static unsigned footprint(unsigned capacity) {
    return sizeof(Set)
      + pad(sizeof(int) * capacity)
      + pad(sizeof(Set::Entry) * capacity);
  }

  Set(unsigned capacity):
    size(0),
    capacity(capacity),
    index(reinterpret_cast<int*>
          (reinterpret_cast<uint8_t*>(this)
           + sizeof(Set))),
    entries(reinterpret_cast<Entry*>
            (reinterpret_cast<uint8_t*>(index) 
             + pad(sizeof(int) * capacity)))
  { }

  unsigned size;
  unsigned capacity;
  int* index;
  Entry* entries;
};

Set*
set(unsigned capacity)
{
  return new (malloc(Set::footprint(capacity))) Set(capacity);
}

void
setDispose(Set* set, void (*dispose)(void*))
{
  if (set) {
    for (unsigned i = 0; i < set->size; ++i) {
      dispose(set->entries[i].value);
    }
    free(set);
  }
}

Set::Entry*
find(Set* set, void* value, unsigned hash,
     bool (*equal)(const void*, const void*))
{
  if (set == 0) return 0;

  for (int i = set->index[hash & (set->capacity - 1)]; i >= 0;) {
    Set::Entry* e = set->entries + i;
    if (equal(e->value, value)) {
      return e;
    }
    i = e->next;
  }

  return 0;
}

Set::Entry*
add(Set* set, void* value, unsigned hash)
{
  unsigned index = hash & (set->capacity - 1);
  int offset = set->size++;

  Set::Entry* e = set->entries + offset;
  e->value = value;
  e->hash = hash;

  e->next = set->index[index];
  set->index[index] = offset;

  return e;
}

Set::Entry*
add(Set** setp, void* value, unsigned hash)
{
  Set* set = *setp;

  if (set == 0 or set->size == set->capacity) {
    unsigned capacity;
    if (set) {
      capacity = set->capacity * 2;
    } else {
      capacity = 4096; // must be power of two
    }

    Set* newSet = ::set(capacity);

    memset(newSet->index, 0xFF, sizeof(int) * capacity);

    if (set) {
      for (unsigned i = 0; i < set->capacity; ++i) {
        for (int j = set->index[i]; j >= 0;) {
          Set::Entry* e = set->entries + j;
          add(newSet, e->value, e->hash);
          j = e->next;
        }
      }

      free(set);
    }

    *setp = set = newSet;
  }

  return add(set, value, hash);
}

class Trace {
 public:
  class Element {
   public:
    Element(uintptr_t address): address(address), symbol(0), next(0) { }

    uintptr_t address;
    const char* symbol;
    Element* next;
  };

  Trace(): count(0), elements(0) { }

  unsigned count;
  Element* elements;
};

Trace*
trace()
{
  return new (malloc(sizeof(Trace))) Trace;
}

void
traceDispose(Trace* t)
{
  if (t) {
    for (Trace::Element* e = t->elements; e;) {
      Trace::Element* n = e->next;
      free(e);
      e = n;
    }
    free(t);
  }
}

Trace::Element*
traceElement(uintptr_t address)
{
  return new (malloc(sizeof(Trace::Element))) Trace::Element(address);
}

unsigned
hash(Trace* t)
{
  unsigned h = 0;
  for (Trace::Element* e = t->elements; e; e = e->next) {
    h ^= e->address;
  }
  return h;
}

int
traceCountCompare(const Trace** a, const Trace** b)
{
  return (*b)->count - (*a)->count;
}

int
traceCompare(const Trace** a, const Trace** b)
{
  Trace::Element* ea = (*a)->elements;
  Trace::Element* eb = (*b)->elements;
  while (true) {
    if (ea and eb) {
      if (ea->address == eb->address) {
        ea = ea->next;
        eb = eb->next;
      } else if (ea->address > eb->address) {
        return -1;
      } else {
        return 1;
      }
    } else if (ea) {
      return -1;
    } else if (eb) {
      return 1;
    } else {
      return 0;
    }
  }
}

bool
traceEqual(const Trace* a, const Trace* b)
{
  return traceCompare(&a, &b) == 0;
}

void
add(Trace* t, Trace::Element** last, uintptr_t address)
{
  Trace::Element* e = traceElement(address);
  if (*last) {
    (*last)->next = e;
  } else {
    t->elements = e;
  }
  *last = e;
}

class Context {
 public:
  Context(pid_t process): process(process), traces(0) { }

  ~Context() {
    setDispose(traces, reinterpret_cast<void (*)(void*)>(traceDispose));
  }

  pid_t process;
  Set* traces;
};

bool
accept(ElfFileHeader* header, unsigned size)
{
  return size >= sizeof(ElfFileHeader)
    and memcmp(&(header->e_ident[EI_MAG0]), ELFMAG, SELFMAG) == 0
    and header->e_ident[EI_CLASS] == ElfClass
    and header->e_ident[EI_DATA] == ELFDATA2LSB
    and header->e_ident[EI_VERSION] == EV_CURRENT
    and header->e_version == EV_CURRENT
    and header->e_machine == ElfArchitecture;
}

bool
accept(ElfSymbol* symbol, unsigned sectionCount)
{
  return symbol->st_shndx != SHN_UNDEF
    and symbol->st_shndx < sectionCount
    and elfType(symbol->st_info) == STT_FUNC;
}

class Symbol {
 public:
  uintptr_t start;
  unsigned size;
  char* name;
};

int
symbolCompare(const Symbol* a, const Symbol* b)
{
  return a->start > b->start ? 1 : (b->start > a->start ? -1 : 0);
}

class SymbolTable {
 public:
  SymbolTable(unsigned capacity): size(0), capacity(capacity) { }

  unsigned size;
  unsigned capacity;
  Symbol symbols[0];
};

SymbolTable*
symbolTable(unsigned capacity)
{
  return new (malloc(sizeof(SymbolTable) + (capacity * sizeof(Symbol))))
    SymbolTable(capacity);
}

void
symbolTableDispose(SymbolTable* t)
{
  if (t) {
    for (unsigned i = 0; i < t->size; ++i) {
      free(t->symbols[i].name);
    }
    free(t);
  }
}

char*
copy(const char* s)
{
  return strdup(s);
}

void
addSymbol(SymbolTable* table, uintptr_t start, unsigned size, const char* name)
{
  Symbol* s = table->symbols + (table->size++);
  s->start = start;
  s->size = size;
  s->name = copy(name);
}

SymbolTable*
append(SymbolTable* a, SymbolTable* b)
{
  if (a and b) {
    SymbolTable* c = symbolTable(a->size + b->size);

    memcpy(c->symbols, a->symbols, a->size * sizeof(Symbol));
    memcpy(c->symbols + a->size, b->symbols, b->size * sizeof(Symbol));

    c->size = a->size + b->size;

    free(a);
    free(b);

    return c;
  } else if (a) {
    return a;
  } else {
    return b;
  }
}

SymbolTable*
readElfSymbolTable(uint8_t* start, unsigned size)
{
  ElfFileHeader* fileHeader = reinterpret_cast<ElfFileHeader*>(start);

  if (accept(fileHeader, size)) {
    unsigned sectionOffset = fileHeader->e_shoff;
    for (int i = 0; i < fileHeader->e_shnum; ++i) {
      ElfSectionHeader* sectionHeader = reinterpret_cast<ElfSectionHeader*>
        (start + sectionOffset);
      sectionOffset += fileHeader->e_shentsize;

      if (sectionHeader->sh_type == SHT_SYMTAB) {
        unsigned count = sectionHeader->sh_size / sizeof(ElfSymbol);

        SymbolTable* table = symbolTable(count);

        ElfSymbol* symbols = reinterpret_cast<ElfSymbol*>
          (start + sectionHeader->sh_offset);

        const char* strings = reinterpret_cast<const char*>
          (start + reinterpret_cast<ElfSectionHeader*>
           (start + fileHeader->e_shoff
            + (sectionHeader->sh_link
               * fileHeader->e_shentsize))->sh_offset);

        for (unsigned j = 0; j < count; ++j) {
          ElfSymbol* symbol = symbols + j;
          if (accept(symbol, fileHeader->e_shnum)) {
            addSymbol(table, symbol->st_value, symbol->st_size,
                      strings + symbol->st_name);
          }
        }

        return table;
      }
    }
  }

  return 0;
}

SymbolTable*
loadElfSymbols(const char* file)
{
  void* data = 0;
  unsigned size = 0;
  int fd = open(file, O_RDONLY);
  if (fd != -1) {
    struct stat s;
    int r = fstat(fd, &s);
    if (r != -1) {
      size = s.st_size;
      data = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    }
    close(fd);
  }

  if (data) {
    SymbolTable* table = readElfSymbolTable(static_cast<uint8_t*>(data), size);

    munmap(data, size);

    return table;
  } else {
    return 0;
  }
}

SymbolTable*
readTextSymbolTable(FILE* in)
{
  const unsigned BufferSize = 1024;
  char buffer[BufferSize];
  SymbolTable* table = symbolTable(1024);

  while (fgets(buffer, BufferSize, in)) {
    if (table->size == table->capacity) {
      SymbolTable* newTable = symbolTable(table->capacity * 2);

      memcpy(newTable->symbols,
             table->symbols,
             table->size * sizeof(Symbol));

      newTable->size = table->size;

      free(table);

      table = newTable;
    }

    void* start;
    void* end;
    char name[BufferSize];
    if (sscanf(buffer, "%p %p %s", &start, &end, name) == 3) {
      addSymbol(table,
                reinterpret_cast<uintptr_t>(start),
                reinterpret_cast<uintptr_t>(end)
                - reinterpret_cast<uintptr_t>(start),
                name);
    }
  }

  return table;
}

SymbolTable*
loadTextSymbols(const char* file)
{
  FILE* in = fopen(file, "rb");
  if (in) {
    SymbolTable* table = readTextSymbolTable(in);

    fclose(in);

    return table;
  } else {
    return 0;
  }
}

const char*
findSymbol(SymbolTable* table, uintptr_t address)
{
  if (table == 0) return 0;

  unsigned bottom = 0;
  unsigned top = table->size;

  for (unsigned span = top - bottom; span; span = top - bottom) {
    unsigned middle = bottom + (span / 2);
    Symbol* s = table->symbols + middle;

    if (address >= s->start and address < s->start + s->size) {
      return s->name;
    } else if (address < s->start) {
      top = middle;
    } else {
      bottom = middle + 1;
    }
  }

  return 0;
}

bool
attach(int thread)
{
  errno = 0;
  ptrace(PTRACE_ATTACH, thread, 0, 0);

  if (errno) fprintf(stderr, "attach %d errno %s\n", thread, strerror(errno));
  
  if (errno) return false;

  int status;
  waitpid(thread, &status, WUNTRACED);

  if (errno == ECHILD) {
    errno = 0;
    while (true) {
      int x = waitpid(-1, &status, __WCLONE);

      if (x == thread or x < 0 or errno) break;
    }
  }

  if (errno) fprintf(stderr, "wait %d errno %s\n", thread, strerror(errno));

  return errno == 0;  
}

void
detach(int thread)
{
  errno = 0;
  ptrace(PTRACE_DETACH, thread, 0, 0);

  if (errno) fprintf(stderr, "detach %d errno %s\n", thread, strerror(errno));

  errno = 0;
}

Trace*
trace(int thread)
{
  Trace* t = trace();
  Trace::Element* last = 0;
  uintptr_t ip = ptrace
    (PTRACE_PEEKUSER, thread, Instruction * BytesPerWord, 0);
//   fprintf(stderr, "ip %p trace %d errno %s\n", ip, thread, strerror(errno));

  if (errno == 0) {
    uintptr_t bp = ptrace
      (PTRACE_PEEKUSER, thread, Base * BytesPerWord, 0);
//     fprintf(stderr, "bp %p trace %d errno %s\n", bp, thread, strerror(errno));

    if (errno == 0) {
      add(t, &last, ip);

      while (errno == 0 and bp) {
        ip = ptrace(PTRACE_PEEKDATA, thread, bp + BytesPerWord, 0);
//         fprintf(stderr, "ra %p trace %d errno %s\n",
//                 ip, thread, strerror(errno));

        if (errno == 0) {
          add(t, &last, ip);
          
          uintptr_t next = ptrace(PTRACE_PEEKDATA, thread, bp, 0);
//           fprintf(stderr, "next bp %p trace %d errno %s\n",
//                   next, thread, strerror(errno));
          if (errno or next <= bp) {
            break;
          } else {
            bp = next;
          }
        }
      }
    }
  }

  return t;
}

void
sample(Context* c)
{
  const unsigned BufferSize = 256;
  char buffer[BufferSize];
  snprintf(buffer, BufferSize, "/proc/%d/task", c->process);

  DIR* d = opendir(buffer);
  for (dirent* e = readdir(d); e; e = readdir(d)) {
    int thread = atoi(e->d_name);
    if (thread and attach(thread)) {
      Trace* t = trace(thread);
      unsigned h = hash(t);

      Set::Entry* se = find
        (c->traces, t, h, reinterpret_cast<bool (*)(const void*, const void*)>
         (traceEqual));

      if (se) {
        traceDispose(t);
      } else {
        se = add(&(c->traces), t, h);
      }

      ++ static_cast<Trace*>(se->value)->count;
      
      detach(thread);
    }
  }
  closedir(d);
}

class Method {
 public:
  Method(const char* name): name(name), count(0), childCount(0) { }

  const char* name;
  unsigned count;
  unsigned childCount;
};

Method*
method(const char* name)
{
  return new (malloc(sizeof(Method))) Method(name);
}

void
methodDispose(Method* m)
{
  if (m) {
    free(m);
  }
}

int
methodTotalCompare(const Method** a, const Method** b)
{
  return static_cast<int>((*b)->count)
    - static_cast<int>((*a)->count);
}

int
methodNetCompare(const Method** a, const Method** b)
{
  return static_cast<int>((*b)->count - (*b)->childCount)
    - static_cast<int>((*a)->count - (*a)->childCount);
}

bool
methodEqual(const Method* a, const Method* b)
{
  return strcmp(a->name, b->name) == 0;
}

void
dump(Method* m, FILE* out)
{
  fprintf(out, "%5d %5d %s\n",
          m->count, m->count - m->childCount, m->name);
}

void
dump(Trace* t, FILE* out)
{
  fprintf(out, "%d time(s):\n", t->count);
  for (Trace::Element* e = t->elements; e; e = e->next) {
    fprintf(out, "  at %p", reinterpret_cast<void*>(e->address));
    if (e->symbol) {
      fprintf(out, " %s", e->symbol);
    }
    fprintf(out, "\n");
  }
}

void
dump(Context* c, SymbolTable* symbolTable, FILE* out)
{
  if (symbolTable) {
    qsort(symbolTable->symbols, symbolTable->size, sizeof(Symbol),
          reinterpret_cast<int (*)(const void*, const void*)>(symbolCompare));
  }

  Set* methods = 0;
  Trace** traceArray = 0;
  unsigned total = 0;

  if (c->traces) {
    traceArray = static_cast<Trace**>(malloc(c->traces->size * BytesPerWord));

    for (unsigned i = 0; i < c->traces->size; ++i) {
      Trace* t = static_cast<Trace*>(c->traces->entries[i].value);
      traceArray[i] = t;

      total += t->count;

      for (Trace::Element* e = t->elements; e; e = e->next) {
        const char* s = e->symbol = findSymbol(symbolTable, e->address);
        if (s == 0) {
          s = "(unknown)";
        }

        unsigned h = hash(s);
        Method n(s);

        Set::Entry* se = find
          (methods, &n, h,
           reinterpret_cast<bool (*)(const void*, const void*)>
           (methodEqual));

        Method* m;
        if (se) {
          m = static_cast<Method*>(se->value);
        } else {
          m = method(s);
          add(&methods, m, h);
        }

        m->count += t->count;

        if (e != t->elements) {
          m->childCount += t->count;
        }
      }
    }
  }

  fprintf(out, " total count: %5d\n", total);

  if (methods) {
    Method** methodArray = static_cast<Method**>
      (malloc(methods->size * BytesPerWord));
  
    for (unsigned i = 0; i < methods->size; ++i) {
      methodArray[i] = static_cast<Method*>(methods->entries[i].value);
    }

    fprintf(out, "\nmethods by net count: (total, net, name)\n\n");

    qsort(methodArray, methods->size, sizeof(Method*),
          reinterpret_cast<int (*)(const void*, const void*)>
          (methodNetCompare));

    for (unsigned i = 0; i < methods->size; ++i) {
      dump(methodArray[i], out);
    }

    fprintf(out, "\nmethods by total count: (total, net, name)\n\n");
  
    qsort(methodArray, methods->size, sizeof(Method*),
          reinterpret_cast<int (*)(const void*, const void*)>
          (methodTotalCompare));

    for (unsigned i = 0; i < methods->size; ++i) {
      dump(methodArray[i], out);
    }

    free(methodArray);
    setDispose(methods, reinterpret_cast<void (*)(void*)>(methodDispose));
  }

  if (c->traces) {
    fprintf(out, "\ntraces by count:\n\n");

    qsort(traceArray, c->traces->size, sizeof(Trace*),
          reinterpret_cast<int (*)(const void*, const void*)>
          (traceCountCompare));

    for (unsigned i = 0; i < c->traces->size; ++i) {
      dump(traceArray[i], out);
      fprintf(out, "\n");
    }

    free(traceArray);
  }
}

void
usage(const char* name)
{
  fprintf(stderr,
          "usage: %s [-o <output file>] [-s <symbol file>] "
          "<command> [<argument>...]\n",
          name);
}

} // namespace

int
main(int ac, char** av)
{
  const char* outputFile = 0;
  const char* symbolFile = 0;
  int commandStart = 1;

  for (int i = 1; i < ac; ++i) {
    if (strcmp(av[i], "-o") == 0) {
      if (i + 1 < ac) {
        outputFile = av[++i];
      } else {
        usage(av[0]);
        return -1;
      }
    } else if (strcmp(av[i], "-s") == 0) {
      if (i + 1 < ac) {
        symbolFile = av[++i];
      } else {
        usage(av[0]);
        return -1;
      }
    } else {
      commandStart = i;
      break;
    }
  }

  if (commandStart == ac) {
    usage(av[0]);
    return -1;
  }

  const char* command = av[commandStart];

  pid_t process = fork();
  if (process == 0) { // child
    execv(command, av + commandStart);
  } else if (process < 0) { // error
    fprintf(stderr, "unable to fork\n");
    return -1;
  } else { // parent
    struct sigaction action;
    action.sa_sigaction = handleSignal;
    action.sa_flags = SA_SIGINFO;

    sigaction(SIGCHLD, &action, 0);
    sigaction(SIGINT, &action, 0);

    timespec interval = { 0, 1000000L };

    Context context(process);

    while (not done) {
      sample(&context);
      nanosleep(&interval, 0);
    }

    FILE* out = stdout;
    if (outputFile) {
      out = fopen(outputFile, "wb");
      if (out == 0) {
        fprintf(stderr, "unable to open %s\n", outputFile);
        return -1;
      }
    }

    SymbolTable* symbols = loadElfSymbols(command);

    if (symbolFile) {
      symbols = append(symbols, loadTextSymbols(symbolFile));
    }

    dump(&context, symbols, out);

    symbolTableDispose(symbols);

    if (outputFile) {
      fclose(out);
    }
  }

  return 0;
}
