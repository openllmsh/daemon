// AppContainer command profile used by the shipped native worker.
// Construction is derived from the cycle-002/004 measured launcher.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

static class OpenllmAppContainer {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup { public int cb;public string reserved,desktop,title;public int x,y,xSize,ySize,xCount,yCount,fill,flags;public short show,reserved2;public IntPtr reservedPtr,input,output,error; }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx {public Startup startup;public IntPtr attributes;}
    [StructLayout(LayoutKind.Sequential)] struct Proc {public IntPtr process,thread;public int pid,tid;}
    [StructLayout(LayoutKind.Sequential)] struct Caps {public IntPtr sid,capabilities;public uint count,reserved;}
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttrs {public int length;public IntPtr descriptor;[MarshalAs(UnmanagedType.Bool)] public bool inherit;}
    [StructLayout(LayoutKind.Sequential)] struct SidAttrs {public IntPtr sid;public uint attrs;}
    [StructLayout(LayoutKind.Sequential)] struct BasicLimit {public long processTime,jobTime;public uint flags;public UIntPtr minWorking,maxWorking;public uint active;public UIntPtr affinity;public uint priority,scheduling;}
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {public ulong a,b,c,d,e,f;}
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {public BasicLimit basic;public IoCounters io;public UIntPtr processMemory,jobMemory,peakProcess,peakJob;}
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int CreateAppContainerProfile(string name,string display,string description,IntPtr capabilities,uint count,out IntPtr sid);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeleteAppContainerProfile(string name);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int GetAppContainerFolderPath(string sid,out IntPtr path);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserProfileDirectoryW(IntPtr token,StringBuilder path,ref uint size);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint desired,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,out int value,int length,out int returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string cwd,ref StartupEx startup,out Proc process);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(ref SecurityAttrs attrs,string name);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenJobObjectW(uint access,bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimit info,int length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr info,int length,out int returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out ExtendedLimit info,int length,out int returned);
    static int[] JobPids(IntPtr job){IntPtr buffer=Marshal.AllocHGlobal(520);try{int returned;Check(QueryInformationJobObject(job,3,buffer,520,out returned),"Query owned job members");int count=Marshal.ReadInt32(buffer,4);if(count<0||count>64)throw new Exception("Job member bound exceeded");int[] pids=new int[count];for(int i=0;i<count;i++)pids[i]=(int)Marshal.ReadInt64(buffer,8+i*8);return pids;}finally{Marshal.FreeHGlobal(buffer);}}

    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr handle);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string path,uint access,uint share,ref SecurityAttrs attrs,uint disposition,uint flags,IntPtr template);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll",SetLastError=true)] static extern bool SetProcessWindowStation(IntPtr station);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateWindowStationW(string name,uint flags,uint access,ref SecurityAttrs attrs);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateDesktopW(string name,IntPtr device,IntPtr mode,uint flags,uint access,ref SecurityAttrs attrs);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll")] static extern bool CloseWindowStation(IntPtr station);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorSacl(IntPtr descriptor,out bool present,out IntPtr sacl,out bool defaulted);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfoW(string name,int kind,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    static void LowIntegrity(string path){IntPtr sd;uint size;Check(ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(ML;;NW;;;LW)",1,out sd,out size),"Create fixture low label");try{bool present,defaulted;IntPtr sacl;Check(GetSecurityDescriptorSacl(sd,out present,out sacl,out defaulted)&&present,"Read fixture low label");uint code=SetNamedSecurityInfoW(path,1,0x10,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,sacl);if(code!=0)throw new Win32Exception((int)code,"Label own fixture directory");}finally{LocalFree(sd);}}
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SecurityAttrs security,int size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(IntPtr handle,byte[] bytes,int count,out int read,IntPtr overlapped);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteFile(IntPtr handle,byte[] bytes,int count,out int written,IntPtr overlapped);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string path,ref SecurityAttrs attrs);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr handle,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr handle,out FileInfoNative info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool result);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessMitigationPolicy(IntPtr process,int policy,out uint flags,UIntPtr size);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateEventW(ref SecurityAttrs attrs,bool manualReset,bool initial,string name);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenEventW(uint access,bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetEvent(IntPtr handle);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr value,int length,out int returned);
    [StructLayout(LayoutKind.Sequential)] struct FileInfoNative {public uint attributes;public System.Runtime.InteropServices.ComTypes.FILETIME created,accessed,written;public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;}
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer {MaxJsonLength=131072};
    static readonly object OutputLock=new object();
    static volatile bool Cancelled,OutputFailed,InputFailed;
    static volatile bool CancellationClosing;
    static long OutputBytes;
    static IntPtr OwnedJob;
    static bool RequireWin32kDenial;
    static readonly object JobLock=new object();
    const uint TaskJobFlags=0x2000|0x8|0x200; // kill on close, active count, Job memory
    const uint TaskActiveProcessLimit=16;
    const uint TaskJobMemoryLimit=512u*1024u*1024u;
    const uint StatusDllInitFailed=0xc0000142;
    static void Check(bool ok,string name){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),name);}
    static void AttestLaunch(IntPtr process,IntPtr input,IntPtr output,IntPtr error){
        bool member;Check(IsProcessInJob(process,OwnedJob,out member)&&member,"Attest creation-time Job");
        ExtendedLimit limits;int returned;
        Check(QueryInformationJobObject(OwnedJob,9,out limits,Marshal.SizeOf(typeof(ExtendedLimit)),out returned),"Read task Job bounds");
        if(limits.basic.flags!=TaskJobFlags||limits.basic.active!=TaskActiveProcessLimit||limits.jobMemory.ToUInt64()!=TaskJobMemoryLimit)
            throw new InvalidOperationException("Task Job bounds differ");
        if(GetFileType(input)!=3||GetFileType(output)!=3||GetFileType(error)!=3)
            throw new InvalidOperationException("Task standard handles are not pipes");
    }
    static void Attest(IntPtr process,string expectedSid){
        if(RequireWin32kDenial){uint flags;Check(GetProcessMitigationPolicy(process,4,out flags,new UIntPtr(4)),"Query task Win32k policy");if((flags&1)==0)throw new InvalidOperationException("Task Win32k calls are not denied");}
        IntPtr token;Check(OpenProcessToken(process,8,out token),"Query task token");
        try{int app,returned;Check(GetTokenInformation(token,29,out app,4,out returned),"Read task token");if(app!=1)throw new InvalidOperationException("Task token is not AppContainer");
            int size=0;GetTokenInformation(token,31,IntPtr.Zero,0,out size);if(size<IntPtr.Size||size>1024)throw new InvalidOperationException("Invalid package SID size");
            IntPtr info=Marshal.AllocHGlobal(size);try{Check(GetTokenInformation(token,31,info,size,out returned),"Read package SID");if(new SecurityIdentifier(Marshal.ReadIntPtr(info)).Value!=expectedSid)throw new InvalidOperationException("Task package SID differs");}finally{Marshal.FreeHGlobal(info);}
        }finally{CloseHandle(token);}
    }
    static void Send(object value){lock(OutputLock){Console.Out.WriteLine(Json.Serialize(value));Console.Out.Flush();}}
    static string ReadBoundedLine(int limit){var b=new StringBuilder();for(;;){int c=Console.In.Read();if(c<0)return b.Length==0?null:b.ToString();if(c==10)return b.ToString();if(b.Length>=limit)throw new InvalidDataException("Request exceeds limit");b.Append((char)c);}}
    static void Stop(){Cancelled=true;lock(JobLock){if(OwnedJob!=IntPtr.Zero)TerminateJobObject(OwnedJob,125);}}
    static string CancelEventName(int pid){return "Local\\OpenLLM.TaskCancel."+pid;}
    static IntPtr CreateCancelEvent(string owner){
        IntPtr sd;uint size;Check(ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;"+owner+")",1,out sd,out size),"Task cancellation descriptor");
        try{var sa=new SecurityAttrs {length=Marshal.SizeOf(typeof(SecurityAttrs)),descriptor=sd,inherit=false};
            IntPtr handle=CreateEventW(ref sa,true,false,CancelEventName(Process.GetCurrentProcess().Id));int error=Marshal.GetLastWin32Error();
            Check(handle!=IntPtr.Zero,"Create task cancellation event");
            if(error==183){CloseHandle(handle);throw new InvalidOperationException("Task cancellation event already exists");}return handle;
        }finally{LocalFree(sd);}
    }
    // Called only by the ConPTY owner before terminating its own Job. No
    // breakaway is allowed: controllers get a bounded chance to remove scratch,
    // then the caller still kills every member regardless of cooperation.
    public static void CancelOwnedControllers(IntPtr job){
        var processes=new List<IntPtr>();IntPtr buffer=Marshal.AllocHGlobal(8200);var elapsed=Stopwatch.StartNew();
        try{
            int returned;if(!QueryInformationJobObject(job,3,buffer,8200,out returned))return;
            int count=Marshal.ReadInt32(buffer,4);if(count<0||count>1024)return;
            for(int i=0;i<count;i++){
                int pid=(int)Marshal.ReadInt64(buffer,8+i*8);IntPtr process=OpenProcess(0x101000,false,pid);if(process==IntPtr.Zero)continue;
                bool retained=false;
                try{bool member;if(!IsProcessInJob(process,job,out member)||!member||WaitForSingleObject(process,0)!=0x102)continue;
                    IntPtr signal=OpenEventW(2,false,CancelEventName(pid));if(signal==IntPtr.Zero)continue;
                    try{if(SetEvent(signal)){processes.Add(process);retained=true;}}finally{CloseHandle(signal);}
                }finally{if(!retained)CloseHandle(process);}
            }
            foreach(IntPtr process in processes){long remaining=5000-elapsed.ElapsedMilliseconds;if(remaining<=0)break;WaitForSingleObject(process,(uint)remaining);}
        }finally{foreach(IntPtr process in processes)CloseHandle(process);Marshal.FreeHGlobal(buffer);}
    }
    static Thread Pump(IntPtr handle,string stream){var thread=new Thread(()=>{try{byte[] data=new byte[8192];int count;while(ReadFile(handle,data,data.Length,out count,IntPtr.Zero)&&count>0){if(Interlocked.Add(ref OutputBytes,count)>1048576){OutputFailed=true;Stop();break;}Send(new {t="output",stream=stream,data=Convert.ToBase64String(data,0,count)});}}catch{OutputFailed=true;Stop();}});thread.IsBackground=true;thread.Start();return thread;}
    // The feeder exclusively owns the non-inheritable writer after Start.
    // Job termination closes all workload readers before cleanup joins it.
    static Thread FeedInput(IntPtr handle,byte[] script){
        var thread=new Thread(()=>{
            try{
                for(int offset=0;offset<script.Length;){
                    int count=Math.Min(4096,script.Length-offset);var chunk=new byte[count];Array.Copy(script,offset,chunk,0,count);int written;
                    if(!WriteFile(handle,chunk,count,out written,IntPtr.Zero)){
                        int error=Marshal.GetLastWin32Error();if(error==109||error==232)return;
                        throw new Win32Exception(error,"Write task input");
                    }
                    if(written<=0||written>count)throw new IOException("Invalid task input write count");offset+=written;
                }
            }catch{InputFailed=true;Stop();}finally{CloseHandle(handle);}
        });thread.IsBackground=true;thread.Start();return thread;
    }
    static string Hash(Stream stream){using(var sha=System.Security.Cryptography.SHA256.Create())return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
    // Hold all ancestors against rename/reparse replacement. A task never gets
    // a writable handle to these directories or to its command input.
    sealed class PinnedDirectory:IDisposable {
        readonly List<IntPtr> handles=new List<IntPtr>();
        public PinnedDirectory(string path){try{string full=Path.GetFullPath(path);if(full!=path||full.Length<4||full[1]!=':'||full.Substring(3).Contains(":"))throw new InvalidDataException("Noncanonical task parent");string current=full.Substring(0,3);Pin(current);foreach(string part in full.Substring(3).Split('\\')){if(part.Length==0||part.EndsWith(".")||part.EndsWith(" "))throw new InvalidDataException("Noncanonical task parent");current=Path.Combine(current,part);Pin(current);}}catch{Dispose();throw;}}
        void Pin(string path){var sa=new SecurityAttrs {length=Marshal.SizeOf(typeof(SecurityAttrs))};IntPtr h=CreateFileW(path,0x80000000,1,ref sa,3,0x02000000|0x00200000,IntPtr.Zero);Check(h!=new IntPtr(-1),"Pin task ancestor");handles.Add(h);FileInfoNative info;Check(GetFileInformationByHandle(h,out info),"Inspect task ancestor");if((info.attributes&0x400)!=0||(info.attributes&0x10)==0)throw new InvalidDataException("Task ancestor is a reparse point");var actual=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,actual,(uint)actual.Capacity,0);Check(n>0&&n<actual.Capacity,"Resolve task ancestor");string value=actual.ToString();if(value.StartsWith(@"\\?\"))value=value.Substring(4);if(!String.Equals(value.TrimEnd('\\'),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Task ancestor changed");}
        public void Dispose(){for(int i=handles.Count-1;i>=0;i--)CloseHandle(handles[i]);handles.Clear();}
    }
    static void CreateOwnedDirectory(string path,string owner){IntPtr sd;uint size;Check(ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;OICI;FA;;;"+owner+")",1,out sd,out size),"Task directory descriptor");try{var sa=new SecurityAttrs {length=Marshal.SizeOf(typeof(SecurityAttrs)),descriptor=sd};Check(CreateDirectoryW(path,ref sa),"Create unique task directory");}finally{LocalFree(sd);}}

    // The OS grants a lowbox its package tree by default. The task contract only
    // grants writable work; keep this new OS profile readable, never writable.
    static void SealPackageTree(string packageRoot,string parent,string name,string owner,SecurityIdentifier package){
        string root=Path.GetDirectoryName(packageRoot),expected=Path.Combine(parent,"Packages",name);
        if(!String.Equals(Path.GetFileName(packageRoot),"AC",StringComparison.OrdinalIgnoreCase)||!String.Equals(root,expected,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Unexpected OS package path");
        int count=0;using(var pin=new PinnedDirectory(root)){SealPackageEntry(root,owner,package,0,ref count);}
    }
    static void SealPackageEntry(string path,string owner,SecurityIdentifier package,int depth,ref int count){
        if(depth>12||++count>256)throw new InvalidDataException("OS package entry bound exceeded");
        var sa=new SecurityAttrs {length=Marshal.SizeOf(typeof(SecurityAttrs))};IntPtr h=CreateFileW(path,0x80000000,1,ref sa,3,0x02000000|0x00200000,IntPtr.Zero);Check(h!=new IntPtr(-1),"Pin new OS package entry");
        try{
            FileInfoNative info;Check(GetFileInformationByHandle(h,out info),"Inspect OS package entry");
            bool directory=(info.attributes&0x10)!=0;
            if((info.attributes&0x400)!=0||(!directory&&info.links!=1))throw new InvalidDataException("Aliased OS package entry");
            FileSystemSecurity previous=directory?(FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);
            string actual=((SecurityIdentifier)previous.GetOwner(typeof(SecurityIdentifier))).Value;
            if(actual!=owner&&!(owner=="S-1-5-18"&&actual=="S-1-5-32-544"))throw new InvalidDataException("OS package owner differs");
            FileSystemSecurity acl=directory?(FileSystemSecurity)new DirectorySecurity():new FileSecurity();acl.SetAccessRuleProtection(true,false);
            var inherit=directory?InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit:InheritanceFlags.None;
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(owner),FileSystemRights.FullControl,inherit,PropagationFlags.None,AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(package,FileSystemRights.ReadAndExecute,inherit,PropagationFlags.None,AccessControlType.Allow));
            if(directory){Directory.SetAccessControl(path,(DirectorySecurity)acl);foreach(string child in Directory.GetFileSystemEntries(path))SealPackageEntry(child,owner,package,depth+1,ref count);}
            else File.SetAccessControl(path,(FileSecurity)acl);
        }finally{CloseHandle(h);}
    }

    // OS-created package registry storage is outside declared work. Seal only
    // this fresh profile before launch, including both registry views and children.
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegOpenKeyExW(IntPtr key,string subkey,uint options,uint access,out IntPtr result);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryValueExW(IntPtr key,string value,IntPtr reserved,out uint type,IntPtr data,ref uint size);
    static void SealPackageRegistry(string name,string owner,SecurityIdentifier package){
        const string storage=@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\";
        int count=0;SealRegistryEntry(Microsoft.Win32.Registry.CurrentUser.Handle.DangerousGetHandle(),storage+name,owner,package,0,ref count);
    }
    static void SealRegistryEntry(IntPtr parent,string name,string owner,SecurityIdentifier package,int depth,ref int count){
        if(depth>12||++count>256)throw new InvalidDataException("OS package registry entry bound exceeded");
        IntPtr handle;int error=RegOpenKeyExW(parent,name,8,0x20019|0x40000|0x100,out handle);
        if(error!=0)throw new Win32Exception(error,"Open new package registry entry without following links");
        using(var safe=new SafeRegistryHandle(handle,true))using(var key=Microsoft.Win32.RegistryKey.FromHandle(safe,Microsoft.Win32.RegistryView.Registry64)){
            uint type,size=0;int found=RegQueryValueExW(handle,"SymbolicLinkValue",IntPtr.Zero,out type,IntPtr.Zero,ref size);
            if(found!=0&&found!=2&&found!=234)throw new Win32Exception(found,"Inspect package registry entry");
            if((found==0||found==234)&&type==6)throw new InvalidDataException("Aliased package registry entry");
            string actual=((SecurityIdentifier)key.GetAccessControl().GetOwner(typeof(SecurityIdentifier))).Value;
            if(actual!=owner&&!(owner=="S-1-5-18"&&actual=="S-1-5-32-544"))throw new InvalidDataException("Unexpected package registry owner");
            var acl=new RegistrySecurity();acl.SetAccessRuleProtection(true,false);
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(owner),RegistryRights.FullControl,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
            acl.AddAccessRule(new RegistryAccessRule(package,RegistryRights.ReadKey,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
            key.SetAccessControl(acl);
            foreach(string child in key.GetSubKeyNames())SealRegistryEntry(handle,child,owner,package,depth+1,ref count);
        }
    }

    static string TaskParent(){
        // Use the current security identity, not caller-controlled HOME or
        // APPDATA variables. Ancestors must still exist and pass pinning.
        using(var identity=WindowsIdentity.GetCurrent()){
            uint size=32768;var profile=new StringBuilder((int)size);
            Check(GetUserProfileDirectoryW(identity.Token,profile,ref size),"Resolve controller token profile");
            return Path.Combine(profile.ToString(),"AppData","Local");
        }
    }
    static void DeleteTree(string path){var attrs=File.GetAttributes(path);if((attrs&FileAttributes.ReparsePoint)!=0){if((attrs&FileAttributes.Directory)!=0)Directory.Delete(path,false);else File.Delete(path);return;}if((attrs&FileAttributes.Directory)==0){File.Delete(path);return;}foreach(string child in Directory.GetFileSystemEntries(path))DeleteTree(child);Directory.Delete(path,false);}


    static string TaskJobName(string name){return "Local\\OpenLLM.Task."+name;}
    static IntPtr CreateTaskJob(string name,string owner){
        IntPtr sd;uint size;Check(ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;"+owner+")",1,out sd,out size),"Task Job descriptor");
        try{var sa=new SecurityAttrs {length=Marshal.SizeOf(typeof(SecurityAttrs)),descriptor=sd,inherit=false};IntPtr job=CreateJobObjectW(ref sa,TaskJobName(name));int error=Marshal.GetLastWin32Error();Check(job!=IntPtr.Zero,"Create task Job");if(error==183){CloseHandle(job);throw new InvalidOperationException("Task Job already exists");}return job;}finally{LocalFree(sd);}
    }
    static string LeaseText(string name,string owner){return "openllm-task-recovery-v1\n"+owner+"\n"+name+"\n";}
    static FileStream CreateLease(string root,string name,string owner){
        var lease=new FileStream(Path.Combine(root,".controller-lease"),FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read,4096,FileOptions.WriteThrough);
        try{byte[] data=Encoding.ASCII.GetBytes(LeaseText(name,owner));lease.Write(data,0,data.Length);lease.Flush(true);return lease;}catch{lease.Dispose();throw;}
    }
    static bool RecoveryAcl(string root,string owner,string package){
        var acl=Directory.GetAccessControl(root);if(!acl.AreAccessRulesProtected)return false;
        string actual=((SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier))).Value;
        if(actual!=owner&&!(owner=="S-1-5-18"&&actual=="S-1-5-32-544"))return false;
        bool controller=false;
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))){
            string sid=rule.IdentityReference.Value;
            if(rule.IsInherited||rule.AccessControlType!=AccessControlType.Allow)return false;
            if(sid==owner&&rule.FileSystemRights==FileSystemRights.FullControl){controller=true;continue;}
            if(sid==package&&rule.FileSystemRights==(FileSystemRights.ReadAndExecute|FileSystemRights.Synchronize)&&rule.InheritanceFlags==InheritanceFlags.None)continue;
            return false;
        }
        return controller;
    }
    static string[] RecoverStale(string parent,string owner){
        var security=new MutexSecurity();security.SetAccessRuleProtection(true,false);security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(owner),MutexRights.FullControl,AccessControlType.Allow));
        bool created,held=false;using(var mutex=new Mutex(false,"Global\\OpenLLM.TaskRecovery."+owner,out created,security)){
            try{try{held=mutex.WaitOne(5000);}catch(AbandonedMutexException){held=true;}if(!held)throw new InvalidOperationException("Task recovery lock deadline");return RecoverStaleLocked(parent,owner);}finally{if(held)mutex.ReleaseMutex();}
        }
    }
    static string[] RecoverStaleLocked(string parent,string owner){
        var recovered=new List<string>();var elapsed=Stopwatch.StartNew();
        using(var parentPin=new PinnedDirectory(parent)){
            foreach(string root in Directory.EnumerateDirectories(parent,"openllm-task-*")){
                if(elapsed.ElapsedMilliseconds>5000||recovered.Count>=32)throw new InvalidOperationException("Task recovery bound exceeded");
                string name=Path.GetFileName(root);if(!Regex.IsMatch(name,"^openllm-task-[0-9a-f]{32}$"))continue;
                if((File.GetAttributes(root)&FileAttributes.ReparsePoint)!=0)continue;
                string marker=Path.Combine(root,".controller-lease");if(!File.Exists(marker)||(File.GetAttributes(marker)&FileAttributes.ReparsePoint)!=0)continue;
                IntPtr packageSid=IntPtr.Zero;FileStream lease=null;PinnedDirectory rootPin=null;bool qualified=false;
                try{
                    if(DeriveAppContainerSidFromAppContainerName(name,out packageSid)<0)continue;
                    if(!RecoveryAcl(root,owner,new SecurityIdentifier(packageSid).Value))continue;
                    rootPin=new PinnedDirectory(root);
                    try{lease=new FileStream(marker,FileMode.Open,FileAccess.ReadWrite,FileShare.None);}catch(IOException){continue;}
                    FileInfoNative info;Check(GetFileInformationByHandle(lease.SafeFileHandle.DangerousGetHandle(),out info),"Inspect recovery descriptor");
                    if((info.attributes&0x410)!=0||info.links!=1||lease.Length>512)continue;
                    var data=new byte[(int)lease.Length];int read=0,n;while(read<data.Length&&(n=lease.Read(data,read,data.Length-read))>0)read+=n;
                    if(read!=data.Length||Encoding.ASCII.GetString(data)!=LeaseText(name,owner))continue;
                    IntPtr job=OpenJobObjectW(0xc,false,TaskJobName(name));
                    if(job!=IntPtr.Zero){try{Check(TerminateJobObject(job,125),"Terminate abandoned task Job");var waited=Stopwatch.StartNew();while(JobPids(job).Length>0&&waited.ElapsedMilliseconds<3000)Thread.Sleep(10);if(JobPids(job).Length!=0)throw new InvalidOperationException("Abandoned task Job still occupied");}finally{CloseHandle(job);}}
                    else if(Marshal.GetLastWin32Error()!=2)throw new Win32Exception(Marshal.GetLastWin32Error(),"Open abandoned task Job");
                    int hr=DeleteAppContainerProfile(name);if(hr<0)Marshal.ThrowExceptionForHR(hr);
                    qualified=true;
                }finally{if(lease!=null)lease.Dispose();if(rootPin!=null)rootPin.Dispose();if(packageSid!=IntPtr.Zero)FreeSid(packageSid);}
                if(qualified){DeleteTaskRoot(root);recovered.Add(root);}
            }
        }
        return recovered.ToArray();
    }

    static void DeleteTaskRoot(string root){
        string marker=Path.Combine(root,".controller-lease");foreach(string child in Directory.GetFileSystemEntries(root))if(child!=marker)DeleteTree(child);File.Delete(marker);Directory.Delete(root,false);
    }
    public static int Run(string version){
        OpenllmWindowsWorker.EnsureProcessAdmission();
        // No child is created until the bounded operation descriptor validates.
        string line=ReadBoundedLine(100000);if(line==null)throw new InvalidDataException("Missing task request");
        var request=Json.Deserialize<Dictionary<string,object>>(line);
        if(request==null||request.Count!=3||!request.ContainsKey("v")||(!(request["v"] is int)||(int)request["v"]!=1)||!request.ContainsKey("profile")||!Object.Equals(request["profile"],"windows-cmd-v1")||!request.ContainsKey("script")||!(request["script"] is string))throw new InvalidDataException("Invalid task profile request");
        byte[] script=Convert.FromBase64String((string)request["script"]);if(script.Length==0||script.Length>65536||Convert.ToBase64String(script)!=(string)request["script"])throw new InvalidDataException("Invalid task script size/encoding");
        foreach(byte b in script)if(b==0||b>127)throw new InvalidDataException("windows-cmd-v1 requires ASCII command input");
        string owner=WindowsIdentity.GetCurrent().User.Value,name="openllm-task-"+Guid.NewGuid().ToString("N");
        // Named private window stations require an administrator token. A
        // standard-user command instead denies the GUI subsystem in the kernel;
        // it never receives access to the caller's interactive desktop. This
        // mode supports headless native tools; GUI-dependent runtimes may fail.
        RequireWin32kDenial=!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        string parent=TaskParent(),root=Path.Combine(parent,name),work=Path.Combine(root,"work");
        string[] recoveredRoots=RecoverStale(parent,owner);string packageRoot=null;
        string system=Environment.GetFolderPath(Environment.SpecialFolder.System),windows=Directory.GetParent(system).FullName,executable=Path.Combine(system,"cmd.exe");
        IntPtr sid=IntPtr.Zero,attrs=IntPtr.Zero,capsMemory=IntPtr.Zero,handleList=IntPtr.Zero,mitigationMemory=IntPtr.Zero,envMemory=IntPtr.Zero,station=IntPtr.Zero,desktop=IntPtr.Zero,creationJobs=IntPtr.Zero;
        IntPtr input=IntPtr.Zero,inputWrite=IntPtr.Zero,outRead=IntPtr.Zero,outWrite=IntPtr.Zero,errRead=IntPtr.Zero,errWrite=IntPtr.Zero,cancelEvent=IntPtr.Zero;Thread eventWaiter=null;
        Proc child=new Proc();bool created=false,profile=false,attributesReady=false,ready=false,clean=false;int code=78,remaining=-1;string reason="setup_failed",stage="cancel_event";Thread stdout=null,stderr=null,stdin=null;PinnedDirectory pinned=null;FileStream tool=null,lease=null;
        try{
            cancelEvent=CreateCancelEvent(owner);
            stage="pin_parent";pinned=new PinnedDirectory(parent);CreateOwnedDirectory(root,owner);created=true;lease=CreateLease(root,name,owner);
            stage="create_profile";int hr=CreateAppContainerProfile(name,name,"OpenLLM uncredentialed command task",IntPtr.Zero,0,out sid);if(hr<0)Marshal.ThrowExceptionForHR(hr);profile=true;var package=new SecurityIdentifier(sid);IntPtr folder;int folderResult=GetAppContainerFolderPath(package.Value,out folder);if(folderResult<0)Marshal.ThrowExceptionForHR(folderResult);try{packageRoot=Marshal.PtrToStringUni(folder);}finally{Marshal.FreeCoTaskMem(folder);}
            stage="seal_package_registry";SealPackageRegistry(name,owner,package);
            stage="seal_package";SealPackageTree(packageRoot,parent,name,owner,package);
            stage="root_acl";var rootAcl=Directory.GetAccessControl(root);rootAcl.AddAccessRule(new FileSystemAccessRule(package,FileSystemRights.ReadAndExecute,AccessControlType.Allow));Directory.SetAccessControl(root,rootAcl);
            stage="work_acl";CreateOwnedDirectory(work,owner);var workAcl=Directory.GetAccessControl(work);workAcl.AddAccessRule(new FileSystemAccessRule(package,FileSystemRights.Modify,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.SetAccessControl(work,workAcl);LowIntegrity(work);
            // Windows rewrites the lowbox child's LOCALAPPDATA/TEMP using its
            // package name. Prepare those paths inside the declared work root.
            stage="scratch_directories";string temp=Path.Combine(work,"tmp"),local=Path.Combine(work,"AppData","Local"),roaming=Path.Combine(work,"AppData","Roaming"),packageLocal=Path.Combine(local,"Packages",name,"AC");foreach(string p in new[]{temp,local,roaming,Path.Combine(packageLocal,"Temp")})Directory.CreateDirectory(p);
            // Fixed OS-selected image, held read-only for the entire launch.
            stage="pin_tool";if((File.GetAttributes(executable)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("System command is a reparse point");tool=new FileStream(executable,FileMode.Open,FileAccess.Read,FileShare.Read);string toolHash=Hash(tool);
            if(!RequireWin32kDenial){
                stage="private_desktop";IntPtr desktopSd;uint desktopSize;Check(ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;"+owner+")(A;;GA;;;"+package.Value+")S:(ML;;NW;;;LW)",1,out desktopSd,out desktopSize),"Private desktop descriptor");IntPtr previous=GetProcessWindowStation();try{var sa=new SecurityAttrs {length=Marshal.SizeOf(typeof(SecurityAttrs)),descriptor=desktopSd};station=CreateWindowStationW(name,0,0xf037f,ref sa);Check(station!=IntPtr.Zero,"Create private window station");Check(SetProcessWindowStation(station),"Select private station");desktop=CreateDesktopW("default",IntPtr.Zero,IntPtr.Zero,0,0xf01ff,ref sa);Check(desktop!=IntPtr.Zero,"Create private desktop");}finally{Check(SetProcessWindowStation(previous),"Restore window station");LocalFree(desktopSd);}
            }
            stage="input_pipe";var inheritable=new SecurityAttrs {length=Marshal.SizeOf(typeof(SecurityAttrs)),inherit=true};Check(CreatePipe(out input,out inputWrite,ref inheritable,4096),"Create task input pipe");Check(SetHandleInformation(inputWrite,1,0),"Protect task input writer");
            stage="output_pipes";Check(CreatePipe(out outRead,out outWrite,ref inheritable,0),"Create stdout pipe");Check(CreatePipe(out errRead,out errWrite,ref inheritable,0),"Create stderr pipe");Check(SetHandleInformation(outRead,1,0)&&SetHandleInformation(errRead,1,0),"Protect read handles");
            stage="attributes";int attributeCount=RequireWin32kDenial?4:3;IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,attributeCount,0,ref size);attrs=Marshal.AllocHGlobal(size);Check(InitializeProcThreadAttributeList(attrs,attributeCount,0,ref size),"Initialize task attributes");attributesReady=true;
            var caps=new Caps {sid=sid};capsMemory=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Caps)));Marshal.StructureToPtr(caps,capsMemory,false);Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x20009),capsMemory,new IntPtr(Marshal.SizeOf(typeof(Caps))),IntPtr.Zero,IntPtr.Zero),"Set no-network AppContainer");
            handleList=Marshal.AllocHGlobal(IntPtr.Size*3);Marshal.WriteIntPtr(handleList,0,input);Marshal.WriteIntPtr(handleList,IntPtr.Size,outWrite);Marshal.WriteIntPtr(handleList,IntPtr.Size*2,errWrite);Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x20002),handleList,new IntPtr(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero),"Declare three handles");
            if(RequireWin32kDenial){mitigationMemory=Marshal.AllocHGlobal(8);Marshal.WriteInt64(mitigationMemory,0x10000000);Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x20007),mitigationMemory,new IntPtr(8),IntPtr.Zero,IntPtr.Zero),"Deny task Win32k calls");}
            // GetTempPath2 uses SystemTemp for SYSTEM, ignoring TMP/TEMP. Set it
            // only on the confined child; the controller never consumes it.
            stage="environment";var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase){{"SystemRoot",windows},{"WINDIR",windows},{"PATH",system+";"+Path.Combine(system,"WindowsPowerShell","v1.0")},{"COMSPEC",executable},{"HOME",work},{"USERPROFILE",work},{"APPDATA",roaming},{"LOCALAPPDATA",local},{"TEMP",temp},{"TMP",temp},{"TMPDIR",temp},{"SystemTemp",temp}};var block=new StringBuilder();foreach(var pair in env)block.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');block.Append('\0');envMemory=Marshal.StringToHGlobalUni(block.ToString());
            stage="job";OwnedJob=CreateTaskJob(name,owner);Check(OwnedJob!=IntPtr.Zero,"Create task Job");var limits=new ExtendedLimit();limits.basic.flags=0x2000|0x8|0x200;limits.basic.active=16;limits.jobMemory=new UIntPtr(512u*1024u*1024u);Check(SetInformationJobObject(OwnedJob,9,ref limits,Marshal.SizeOf(typeof(ExtendedLimit))),"Set task Job bounds");
            creationJobs=OpenllmWindowsWorker.AddCreationJob(attrs,OwnedJob);
            stage="launch";var startup=new StartupEx();startup.startup.cb=Marshal.SizeOf(typeof(StartupEx));startup.startup.desktop=RequireWin32kDenial?null:name+"\\default";startup.startup.flags=0x100;startup.startup.input=input;startup.startup.output=outWrite;startup.startup.error=errWrite;startup.attributes=attrs;
            Check(CreateProcessW(executable,new StringBuilder("\""+executable+"\" /d /q"),IntPtr.Zero,IntPtr.Zero,true,0x80000|0x08000000|0x4|0x400,envMemory,work,ref startup,out child),"Create suspended task in Job");
            stage="attest_launch";AttestLaunch(child.process,input,outWrite,errWrite);
            object admission=OpenllmWindowsWorker.AttestAdmission(child.process);
            Attest(child.process,package.Value);
            CloseHandle(outWrite);outWrite=IntPtr.Zero;CloseHandle(errWrite);errWrite=IntPtr.Zero;CloseHandle(input);input=IntPtr.Zero;
            // Control is never inherited by the workload. EOF covers controller death.
            var control=new Thread(()=>{try{for(;;){string command=ReadBoundedLine(128);if(command==null){Stop();return;}if(command=="{\"t\":\"cancel\"}"){Stop();return;}Stop();return;}}catch{Stop();}});control.IsBackground=true;control.Start();
            IntPtr cancellationHandle=cancelEvent;
            eventWaiter=new Thread(()=>{if(WaitForSingleObject(cancellationHandle,0xffffffff)==0&&!CancellationClosing)Stop();});eventWaiter.IsBackground=true;eventWaiter.Start();
            if(Cancelled)throw new InvalidOperationException("Controller closed before task start");
            Check(ResumeThread(child.thread)!=0xffffffff,"Resume attested task");ready=true;
            Send(new {t="ready",version=version,profile="windows-cmd-v1",pid=child.pid,controller_pid=Process.GetCurrentProcess().Id,appcontainer=true,network="none",declared_handles=3,creation_job=true,active_process_limit=TaskActiveProcessLimit,stdin_kind="pipe",desktop_mode=RequireWin32kDenial?"headless":"private",win32k_disabled=RequireWin32kDenial,tool_sha256=toolHash,root=root,recovered_roots=recoveredRoots,package_root=packageRoot,admission=admission});
            stdout=Pump(outRead,"stdout");stderr=Pump(errRead,"stderr");
            stdin=FeedInput(inputWrite,script);inputWrite=IntPtr.Zero;
            uint waited;var elapsed=Stopwatch.StartNew();string priorMembers="";bool processLimit=false;
            do { waited=WaitForSingleObject(child.process,100);if(waited!=0x102)break;
                int[] members=JobPids(OwnedJob);string joined=String.Join(",",members);if(joined!=priorMembers){
                    var attested=new List<int>();foreach(int pid in members){IntPtr process=OpenProcess(0x1000,false,pid);if(process==IntPtr.Zero){if(Marshal.GetLastWin32Error()==87)continue;throw new Win32Exception(Marshal.GetLastWin32Error(),"Open Job member");}try{Attest(process,package.Value);attested.Add(pid);}finally{CloseHandle(process);}}
                    priorMembers=joined;Send(new {t="members",pids=attested.ToArray(),appcontainer=true,same_package=true});
                }
                if(members.Length>TaskActiveProcessLimit){processLimit=true;break;}
            } while(elapsed.ElapsedMilliseconds<60000);
            if(processLimit){reason="process_limit";code=125;}else if(waited==0x102){reason="timeout";code=124;}else{Check(waited==0,"Wait for task");uint exit;Check(GetExitCodeProcess(child.process,out exit),"Task exit");code=unchecked((int)exit);reason=Cancelled?"cancelled":exit==StatusDllInitFailed?"loader_init_failed":"completed";}
            if(InputFailed){code=125;reason="input_transport";}else if(OutputFailed){code=125;reason="output_limit_or_transport";}else if(Cancelled){code=125;reason="cancelled";}
        }catch(Exception e){reason=ready?"controller_failed":"setup_failed";code=78;try{Send(new {t="error",code="SANDBOX_UNAVAILABLE",operation=(e is Win32Exception?e.Message+" win32:"+((Win32Exception)e).NativeErrorCode:e.GetType().Name)+" at "+stage});}catch{}}
        finally{
            CancellationClosing=true;if(cancelEvent!=IntPtr.Zero){SetEvent(cancelEvent);if(eventWaiter!=null)eventWaiter.Join(1000);CloseHandle(cancelEvent);}
            if(OwnedJob!=IntPtr.Zero){TerminateJobObject(OwnedJob,125);var wait=Stopwatch.StartNew();while(JobPids(OwnedJob).Length>0&&wait.ElapsedMilliseconds<5000)Thread.Sleep(10);remaining=JobPids(OwnedJob).Length;clean=remaining==0;}
            // Setup can fail before any process or Job is created. Resource
            // deletion below must still succeed before this becomes a clean
            // setup refusal; an unobserved child is never counted as absent.
            else if(child.process==IntPtr.Zero&&child.thread==IntPtr.Zero){remaining=0;clean=true;}
            if(child.process!=IntPtr.Zero&&WaitForSingleObject(child.process,0)!=0){TerminateProcess(child.process,125);if(WaitForSingleObject(child.process,3000)!=0)clean=false;}
            if(stdin!=null&&!stdin.Join(3000))clean=false;if(InputFailed){code=125;reason="input_transport";}
            if(stdout!=null&&!stdout.Join(3000))clean=false;if(stderr!=null&&!stderr.Join(3000))clean=false;
            foreach(IntPtr h in new[]{input,inputWrite,outWrite,errWrite,outRead,errRead,child.thread,child.process})if(h!=IntPtr.Zero&&h!=new IntPtr(-1))CloseHandle(h);
            lock(JobLock){if(OwnedJob!=IntPtr.Zero){IntPtr closing=OwnedJob;OwnedJob=IntPtr.Zero;CloseHandle(closing);}}
            if(attributesReady)DeleteProcThreadAttributeList(attrs);foreach(IntPtr h in new[]{attrs,capsMemory,handleList,mitigationMemory,envMemory,creationJobs})if(h!=IntPtr.Zero)Marshal.FreeHGlobal(h);
            if(desktop!=IntPtr.Zero&&!CloseDesktop(desktop))clean=false;if(station!=IntPtr.Zero&&!CloseWindowStation(station))clean=false;if(tool!=null)tool.Dispose();
            try{if(profile&&DeleteAppContainerProfile(name)<0)clean=false;if(lease!=null){lease.Dispose();lease=null;}if(created)DeleteTaskRoot(root);}catch{clean=false;}
            if(sid!=IntPtr.Zero)FreeSid(sid);if(pinned!=null)pinned.Dispose();
        }
        if(!clean){code=78;reason="cleanup_failed";}
        Send(new {t="exit",code=code,reason=reason,cleanup=clean,remaining=remaining});return code;
    }
}
