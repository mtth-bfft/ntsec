# ntsec

Standalone tool to explore the security model of Windows and its NT kernel. Use it to introspect privilege assignments and access right assignments, enumerate attack surfaces from the point of view of a sandboxed process, etc.

## Usage

```
ntsec.exe [options] <operations>

Operations are processed from commandline from left to right, or in --interactive mode.
Some operations might fail because you lack some privileges, in which case you will be prompted
to confirm an elevation operation, if one is deemed possible. To avoid hanging indefinitely in
case user interaction is impossible, use `-n`.

Supported object types: ALPC port, object directory, event, file (file, directory, named pipe),
minifilter port, job, keyed event, memory partition, mutant, process, registry key, section,
semaphore, service, session, object symbolic link, and thread.

At startup, the calling process is selected. To select a target:
      --nt         <nt_path>                   any NT object, by absolute NT path
      --alpc       <nt_path>                   ALPC connection port, by absolute NT path
      --directory  <nt_path>                   object directory, by absolute NT path
      --event      <nt_path>                   event object, by absolute NT path
   -f --file       <nt_path>|<win32_path>      file or directory object, by NT or Win32 path
      --fltport    <nt_path>                   filter connection port object, by absolute NT path
      --job        <nt_path>                   job object, by absolute NT path
      --keyedevent <nt_path>                   keyed event object, by absolute NT path
      --partition  <nt_path>                   memory partition object, by absolute NT path
      --mutant     <nt_path>                   mutant object, by absolute NT path
      --namedpipe  <nt_path>|<name>            named pipe file, by absolute NT path or name
   -p --process    <pid>|<name>|current|caller process, by .exe name or id
   -r --regkey     <nt_path>|<win32_path>      registry key, by NT or Win32 path
      --section    <nt_path>                   section object, by absolute NT path
      --semaphore  <nt_path>                   semaphore object, by absolute NT path
   -s --service    <name>                      Windows service, by short name
      --session    <nt_path>                   session object, by absolute NT path
      --symlink    <nt_path>                   symbolic link object, by absolute NT path
   -t --thread     <tid>|current               thread, by id or 'current'
      --timer      <nt_path>                   timer object, by absolute NT path

Generic operations for all types:
      --sddl [new_sddl]         show (or replace) the security descriptor, as a SDDL string
      --sd                      show the security descriptor, as full text

Operations on processes:
      --open-token              select the process' primary token
      --list-mitigations        display status of each process mitigation policy
      --list-handles            list all open handles, their target and permissions
      --list-memmap             list all memory mappings and their permissions

Operations on threads:
      --open-token              select the thread' impersonation token, if any

Operations on access tokens:
      --list-sids               lists all SIDs held and their attributes
      --list-privs              lists all privileges held and their status
      --show-token              display user, groups, integrity, privileges, etc.
   -e --enable-priv  <name>     enable a disabled privilege (use * as wildcard)
   -d --disable-priv <name>     disable an enabled privilege (use * as wildcard)
      --remove-priv  <name>     remove a privilege entirely (cannot be undone, use * as wildcard)
      --assign <tid>            set the given thread's impersonation token to be the selected token
      --impersonate             impersonate the selected token for operations that follow
                                (requires SeImpersonatePrivilege)
      --stop-impersonating      stop impersonating for operations that follow
   -x --execute <cmd>           create a process holding a copy of the selected token (requires an opened
                                process with PROCESS_CREATE_PROCESS rights, or SeAssignPrimaryTokenPrivilege)

Enumerate accessible objects (optionally on which we have a specific access right, or another criteria)
Takes privileges/open handles into account. Doesn't select objects, use while impersonating a token:
   --processes-with [access_right]|[sid]|[privilege]
   --threads-with   [access_right]|[sid]|[privilege]
   --regkeys-with   [access_right]
   --files-with     [access_right]
   --ntobjs-with    [access_right]
   --services-with  [access_right]
   --anything-with  [access_right]

Options:
   -i --interactive             pop an interactive pseudo-shell
   -y --yes                     don't prompt for consent, assume yes
   -n --no                      don't prompt for consent, assume no
   -v --verbose                 increase verbosity (can be repeated)
   -h --help                    display this help text
   -V --version                 display the current version
```
