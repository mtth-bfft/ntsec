# ntsec

## Usage

`ntsec.exe [options] <operations>`

Operations are processed *from left to right*. By default, the calling process is selected.
Some operations might fail because you lack some privileges, in which case you will be prompted
to confirm an elevation operation, if one is deemed possible. To avoid hanging indefinitely in
case user interaction is impossible, use `-n`.

Select a securable object:
   -p --process <pid>|<name>|"caller"  select the given process by .exe name or id
   -t --thread  <tid>|"current"        select the given thread by id, or ntsec's main and only thread
   -r --regkey  <key>                  select the given registry key by name
   -f --file    <path>                 select the given file or directory by NT or Win32 path
   -k --kernobj <nt_path>              select the given kernel object (mutex, semaphore, event, job, etc.) by NT path
   -s --service <name>                 select the given service by name

Generic operations for all types:
   --show-sd                     describe security descriptor of the selected object
   --show-sddl                   display SD of the selected object as a string

Operations on processes:
   --open-token                  select the process' primary token
   --steal-token <cmd>           steal the process' primary token by executing the given command as a reparented process

Operations on threads:
   --open-token                  select the thread' impersonation token, if any

Operations on access tokens:
   --show-token                  display user, groups, privileges, etc.
   -e --enable-priv  <name>      enable a disabled privilege (use * as wildcard)
   -d --disable-priv <name>      disable an enabled privilege (use * as wildcard)
   --remove-priv     <name>      remove a privilege entirely (cannot be undone, use * as wildcard)
   --assign <tid>                set the given thread's impersonation token to be the selected token
   --impersonate                 impersonate the selected token for operations that follow
                                 (requires SeImpersonatePrivilege)
   --stop-impersonating          stop impersonating for operations that follow
   -x --execute <cmd>            create a process executing that command, with the selected token
                                 (requires SeAssignPrimaryTokenPrivilege)

Enumerate objects with a given criteria (doesn't select any of them) (mostly useful while impersonating a token):
   --files-with <access_right>                 shows all files on which we have the given access right
   --regkey-with <access_right>                shows all registry keys on which we have the given access right
   --proc-with <access_right|sid|privilege>    shows all processes on which we have the given access right, or who
                                               hold a primary token containing the given SID or privilege name
   --thread-with <access_right|sid|privilege>  shows all threads on which we have the given access right, or who
                                               hold an impersonation token containing the given SID or privilege name

Convenience functions to pretty print security descriptors:
   --explain-sd [<type>:]<sddl>  describe as text the given security descriptor definition language

Options:
   -y --yes                      don't prompt for consent, assume yes
   -n --no                       don't prompt for consent, assume no
   -v --verbose                  increase verbosity (can be repeated)
   -h --help                     display this help text
   -V --version                  display the current version
