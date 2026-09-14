// Native Windows console host. Built by scripts/compile-windows-worker.ps1.
// ConPTY owns the console. A kill-on-close Job Object owns its entire process tree.
// Stdio is a bounded JSON-lines protocol; it is never a network listener.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

class OpenllmWindowsWorker {
    const string Version = "__OPENLLM_NATIVE_VERSION__";
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1048576 };
    static readonly object OutputLock = new object();
    static IntPtr ConsoleHandle, Job, InputWrite;
    static volatile bool Stopping;
    [StructLayout(LayoutKind.Sequential)] struct Coord { public short X, Y; public Coord(int x,int y) { X=(short)x;Y=(short)y; } }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
        public int cb; public string reserved,desktop,title;
        public int x,y,xSize,ySize,xChars,yChars,fill,flags;
        public short show,reserved2; public IntPtr reservedPtr,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup si; public IntPtr attrs; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process,thread; public int pid,tid; }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
        public long processTime,jobTime; public uint flags;
        public UIntPtr minWorking,maxWorking; public uint active;
        public UIntPtr affinity; public uint priority,scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong a,b,c,d,e,f; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
        public BasicLimit basic; public IoCounters io;
        public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,IntPtr security,int size);
    [DllImport("kernel32.dll")] static extern int CreatePseudoConsole(Coord size,IntPtr input,IntPtr output,uint flags,out IntPtr console);
    [DllImport("kernel32.dll")] static extern int ResizePseudoConsole(IntPtr console,Coord size);
    [DllImport("kernel32.dll")] static extern void ClosePseudoConsole(IntPtr console);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr prev,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref StartupEx si,out ProcessInfo pi);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr security,string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimit info,int size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out ExtendedLimit limits,int size,IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr handle,byte[] bytes,int count,out int read,IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr handle,byte[] bytes,int count,out int written,IntPtr overlapped);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetConsoleCtrlHandler(IntPtr handler,bool add);

    static void Check(bool value,string operation) { if(!value) throw new Win32Exception(Marshal.GetLastWin32Error(),operation); }
    static IntPtr AdmissionJob;
    static readonly object AdmissionLock=new object();
    public static void EnsureProcessAdmission() {
        lock(AdmissionLock) {
            if(AdmissionJob==IntPtr.Zero) {
                // Also covers direct native invocation, SCM and ConPTY helpers.
                // Ancestor daemon admission Jobs are inherited, never replaced.
                IntPtr job=CreateJobObject(IntPtr.Zero,null);Check(job!=IntPtr.Zero,"Create process admission Job");
                try {
                    var limit=new ExtendedLimit();limit.basic.flags=0x8;limit.basic.active=16;
                    Check(SetInformationJobObject(job,9,ref limit,Marshal.SizeOf(typeof(ExtendedLimit))),"Set process admission limit");
                    Check(AssignProcessToJobObject(job,GetCurrentProcess()),"Admit caller before child launch");
                    // No kill-on-close: durable hosts retain their inherited
                    // bounds when the daemon/controller exits normally.
                    AdmissionJob=job;
                } catch {CloseHandle(job);throw;}
            }
            bool member;ExtendedLimit actual;
            Check(IsProcessInJob(GetCurrentProcess(),AdmissionJob,out member)&&member,"Verify caller admission");
            Check(QueryInformationJobObject(AdmissionJob,9,out actual,Marshal.SizeOf(typeof(ExtendedLimit)),IntPtr.Zero),"Read process admission limits");
            if((actual.basic.flags&0x8)==0||(actual.basic.flags&0x1800)!=0||actual.basic.active!=16)throw new InvalidOperationException("Process admission policy mismatch");
        }
    }
    public static IntPtr AddCreationJob(IntPtr attrs,IntPtr job) {
        EnsureProcessAdmission();
        IntPtr jobs=Marshal.AllocHGlobal(IntPtr.Size);
        try {
            Marshal.WriteIntPtr(jobs,job);
            // PROC_THREAD_ATTRIBUTE_JOB_LIST: the child joins its nested task
            // Job during creation, not after a suspended process already exists.
            // The process-wide admission Job is inherited from this caller.
            Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x2000d),jobs,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"Set creation Job list");
            return jobs;
        } catch {Marshal.FreeHGlobal(jobs);throw;}
    }
    public static object AttestAdmission(IntPtr child) {
        EnsureProcessAdmission();bool member;
        Check(IsProcessInJob(child,AdmissionJob,out member)&&member,"Verify child admission before resume");
        return new {limit=16,scope="process-tree",prebirth=true,breakaway=false};
    }
    static void Send(object value) { lock(OutputLock) { Console.Out.WriteLine(Json.Serialize(value));Console.Out.Flush(); } }
    static string Quote(string value) {
        // CommandLineToArgvW / Microsoft CRT quoting. No cmd.exe interpolation.
        var b=new StringBuilder("\"");int slashes=0;
        foreach(char c in value) {
            if(c=='\\') {slashes++;continue;}
            if(c=='"') {b.Append('\\',slashes*2+1);b.Append(c);slashes=0;continue;}
            b.Append('\\',slashes);slashes=0;b.Append(c);
        }
        b.Append('\\',slashes*2);b.Append('"');return b.ToString();
    }
    static bool IsCmdExecutable(string executable) {
        string name=Path.GetFileName(executable);
        return String.Equals(name,"cmd",StringComparison.OrdinalIgnoreCase)||String.Equals(name,"cmd.exe",StringComparison.OrdinalIgnoreCase);
    }
    static StringBuilder BuildCommandLine(string[] args) {
        var command=new StringBuilder();
        bool cmdCommand=IsCmdExecutable(args[3])&&Array.Exists(args,a=>String.Equals(a,"/c",StringComparison.OrdinalIgnoreCase));
        if(cmdCommand) {
            // cmd.exe /s /c consumes quotes as its command envelope rather
            // than using CRT argv rules. lpApplicationName selects cmd.exe;
            // preserve only the explicitly requested command payload raw.
            bool commandPayload=false;
            for(int i=4;i<args.Length;i++) {
                if(i>4)command.Append(' ');
                command.Append(commandPayload?args[i]:Quote(args[i]));
                if(String.Equals(args[i],"/c",StringComparison.OrdinalIgnoreCase))commandPayload=true;
            }
        } else for(int i=3;i<args.Length;i++){if(i>3)command.Append(' ');command.Append(Quote(args[i]));}
        return command;
    }
    static void SecureDirectory(string path) {
        var d=new DirectoryInfo(path);
        if(!d.Exists || (d.Attributes & FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("unsafe directory");
        var sid=WindowsIdentity.GetCurrent().User;
        var acl=new DirectorySecurity();acl.SetOwner(sid);acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        d.SetAccessControl(acl);
        CheckDirectory(path);
    }
    static void CheckDirectory(string path) {
        var d=new DirectoryInfo(path);
        if(!d.Exists || (d.Attributes & FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("unsafe directory");
        var sid=WindowsIdentity.GetCurrent().User;var acl=d.GetAccessControl();
        if(!sid.Equals(acl.GetOwner(typeof(SecurityIdentifier)))) throw new InvalidOperationException("directory owner mismatch");
        if(!acl.AreAccessRulesProtected) throw new InvalidOperationException("directory ACL inherits access");
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow && !sid.Equals(rule.IdentityReference)) throw new InvalidOperationException("directory ACL grants another identity");
    }
    static int Identity(string value) {
        int pid;if(!Int32.TryParse(value,out pid)||pid<=0)return 5;
        try { using(var p=Process.GetProcessById(pid)) Console.WriteLine(p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString());return 0; }
        catch(ArgumentException) {return 3;}
        catch(InvalidOperationException) {return 3;}
        catch {return 5;}
    }
    static int Run(string[] args) {
        if(args.Length==1 && args[0]=="--version") {Console.WriteLine("openllm-windows-worker v"+Version);return 0;}
        if(args.Length==1 && args[0]=="--appcontainer-cmd") return OpenllmAppContainer.Run(Version);
        if(args.Length==2 && args[0]=="--identity")return Identity(args[1]);
        if(args.Length==2 && args[0]=="--secure-directory") {SecureDirectory(args[1]);return 0;}
        if(args.Length==2 && args[0]=="--check-directory") {CheckDirectory(args[1]);return 0;}
        if(args.Length==4 && args[0]=="--service") {ServiceBase.Run(new OpenllmDaemonService(args[1],args[2],args[3]));return 0;}
        if(args.Length<4 || args[0]!="--pty")throw new InvalidOperationException("expected --pty cols rows executable [args]");
        int cols=Int32.Parse(args[1]),rows=Int32.Parse(args[2]);
        if(cols<1||cols>500||rows<1||rows>500)throw new InvalidOperationException("invalid dimensions");
        IntPtr inputRead=IntPtr.Zero,outputWrite=IntPtr.Zero,outputRead=IntPtr.Zero,attrs=IntPtr.Zero,creationJobs=IntPtr.Zero;
        ProcessInfo pi=new ProcessInfo();Thread reader=null;
        try {
            Check(CreatePipe(out inputRead,out InputWrite,IntPtr.Zero,0),"CreatePipe input");
            Check(CreatePipe(out outputRead,out outputWrite,IntPtr.Zero,0),"CreatePipe output");
            int hr=CreatePseudoConsole(new Coord(cols,rows),inputRead,outputWrite,0,out ConsoleHandle);
            if(hr!=0)throw new COMException("CreatePseudoConsole",hr);
            IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
            attrs=Marshal.AllocHGlobal(size);
            Check(InitializeProcThreadAttributeList(attrs,2,0,ref size),"InitializeProcThreadAttributeList");
            Check(UpdateProcThreadAttribute(attrs,0,(IntPtr)0x20016,ConsoleHandle,(IntPtr)IntPtr.Size,IntPtr.Zero,IntPtr.Zero),"UpdateProcThreadAttribute");
            Job=CreateJobObject(IntPtr.Zero,null);Check(Job!=IntPtr.Zero,"CreateJobObject");
            var limit=new ExtendedLimit();limit.basic.flags=0x2000;
            Check(SetInformationJobObject(Job,9,ref limit,Marshal.SizeOf(typeof(ExtendedLimit))),"SetInformationJobObject");
            creationJobs=AddCreationJob(attrs,Job);
            var si=new StartupEx();si.si.cb=Marshal.SizeOf(typeof(StartupEx));si.attrs=attrs;
            // Explicit null standard handles bind the child to ConPTY. Without
            // STARTF_USESTDHANDLES Windows duplicates this worker's JSON pipes.
            si.si.flags=0x100;
            var command=BuildCommandLine(args);
            // The parent's ignore-Ctrl+C attribute is inherited by the shell.
            // Clear it before spawning, even under a noninteractive supervisor.
            Check(SetConsoleCtrlHandler(IntPtr.Zero,false),"Reset console control");
            Check(CreateProcessW(args[3],command,IntPtr.Zero,IntPtr.Zero,false,0x80000|0x4|0x400,IntPtr.Zero,Directory.GetCurrentDirectory(),ref si,out pi),"CreateProcessW");
            object admission=AttestAdmission(pi.process);
            Check(ResumeThread(pi.thread)!=0xffffffff,"ResumeThread");
            CloseHandle(inputRead);inputRead=IntPtr.Zero;CloseHandle(outputWrite);outputWrite=IntPtr.Zero;
            Send(new {t="ready",pid=pi.pid,version=Version,admission=admission});
            var outputHandle=outputRead;
            reader=new Thread(()=>{
                try {byte[] b=new byte[8192];int n;while(ReadFile(outputHandle,b,b.Length,out n,IntPtr.Zero)&&n>0) Send(new {t="output",data=Convert.ToBase64String(b,0,n)});}
                catch { if(!Stopping)StopPtyJob(); }
            });reader.IsBackground=true;reader.Start();
            var input=new Thread(()=>{
                try {
                    string line;var stream=Console.OpenStandardInput();var b=new StringBuilder();
                    while(!Stopping) {
                        int ch=stream.ReadByte();if(ch<0)break;
                        if(ch!=10){if(b.Length>=131072)throw new InvalidOperationException("input frame too large");b.Append((char)ch);continue;}
                        line=b.ToString();b.Length=0;
                        var frame=Json.Deserialize<Dictionary<string,object>>(line);var t=(string)frame["t"];
                        if(t=="input") {byte[] data=Convert.FromBase64String((string)frame["data"]);if(data.Length>65536)throw new InvalidOperationException("input too large");int n;Check(WriteFile(InputWrite,data,data.Length,out n,IntPtr.Zero)&&n==data.Length,"WriteFile");}
                        else if(t=="resize") {int x=Convert.ToInt32(frame["cols"]),y=Convert.ToInt32(frame["rows"]);if(x<1||x>500||y<1||y>500)throw new InvalidOperationException("invalid resize");int result=ResizePseudoConsole(ConsoleHandle,new Coord(x,y));if(result!=0)throw new COMException("ResizePseudoConsole",result);}
                        else if(t=="kill")break;
                        else throw new InvalidOperationException("unknown input frame");
                    }
                } catch { /* Malformed/closed owner transport terminates only this job. */ }
                if(!Stopping)StopPtyJob();
            });input.IsBackground=true;input.Start();
            WaitForSingleObject(pi.process,0xffffffff);uint exit;Check(GetExitCodeProcess(pi.process,out exit),"GetExitCodeProcess");
            Stopping=true;
            // Drain the ConPTY's final bytes before delivering the numeric exit.
            ClosePseudoConsole(ConsoleHandle);ConsoleHandle=IntPtr.Zero;
            reader.Join(3000);
            Send(new {t="exit",code=unchecked((int)exit)});return 0;
        } finally {
            Stopping=true;
            lock(PtyStopLock){if(Job!=IntPtr.Zero) {StopPtyJob();CloseHandle(Job);Job=IntPtr.Zero;}}
            if(ConsoleHandle!=IntPtr.Zero) {ClosePseudoConsole(ConsoleHandle);ConsoleHandle=IntPtr.Zero;}
            foreach(var h in new[]{inputRead,InputWrite,outputWrite,outputRead,pi.thread,pi.process})if(h!=IntPtr.Zero)CloseHandle(h);
            if(attrs!=IntPtr.Zero){DeleteProcThreadAttributeList(attrs);Marshal.FreeHGlobal(attrs);}
            if(creationJobs!=IntPtr.Zero)Marshal.FreeHGlobal(creationJobs);
        }
    }
    static readonly object PtyStopLock=new object();
    static bool PtyCancellationRequested;
    static void StopPtyJob(){lock(PtyStopLock){if(Job==IntPtr.Zero)return;if(!PtyCancellationRequested){PtyCancellationRequested=true;try{OpenllmAppContainer.CancelOwnedControllers(Job);}catch{/* The outer Job still terminates on cancellation failure. */}}TerminateJobObject(Job,1);}}
    static int Main(string[] args) {try{EnsureProcessAdmission();return Run(args);}catch(Exception e){Console.Error.WriteLine("windows-worker: "+e.GetType().Name+" "+e.Message+(e is Win32Exception ? " code="+((Win32Exception)e).NativeErrorCode : ""));return 1;}}
}

// SCM supervises this adapter. Its child is the real compiled daemon. Stopping
// the service asks its owned daemon to drain and exit; durable hosts survive.
class OpenllmDaemonService : ServiceBase {
    readonly string Binary, State, EnvFile;
    readonly object Sync = new object();
    Process Child;
    volatile bool Stopping;
    public OpenllmDaemonService(string binary,string state,string envFile) {
        ServiceName="OpenLLMD";AutoLog=false;CanStop=true;CanShutdown=true;
        Binary=binary;State=state;EnvFile=envFile;
    }
    protected override void OnStart(string[] args) {
        if(!Path.IsPathRooted(Binary)||!Path.IsPathRooted(State)||!Path.IsPathRooted(EnvFile))throw new InvalidOperationException("Service paths must be absolute");
        var start=new ProcessStartInfo(Binary) {UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=State,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        start.EnvironmentVariables["OPENLLM_DAEMON_STATE_DIR"]=State;
        start.EnvironmentVariables["OPENLLM_DAEMON_ENV_FILE"]=EnvFile;
        start.EnvironmentVariables["OPENLLM_DAEMON_DEV"]="0";
        start.EnvironmentVariables["OPENLLM_SERVICE_CONTROL"]="stdio-v1";
        Child=new Process {StartInfo=start,EnableRaisingEvents=true};
        Child.OutputDataReceived+=(s,e)=>{if(e.Data!=null)WriteLog("openllmd.out.log",e.Data);};
        Child.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)WriteLog("openllmd.err.log",e.Data);};
        Child.Exited+=(s,e)=>{if(!Stopping){ExitCode=1;ThreadPool.QueueUserWorkItem(_=>Stop());}};
        if(!Child.Start())throw new InvalidOperationException("Daemon start failed");
        Child.BeginOutputReadLine();Child.BeginErrorReadLine();
    }
    void WriteLog(string file,string line) {
        try{lock(Sync)File.AppendAllText(Path.Combine(State,file),line+Environment.NewLine);}catch{}
    }
    protected override void OnStop() {
        Stopping=true;
        if(Child==null)return;
        try {
            if(!Child.HasExited) {
                // SCM shutdown notifications need not enter STOP_PENDING.
                // A refused wait hint must not skip the actual stop request.
                try {RequestAdditionalTime(15000);} catch(InvalidOperationException) {}
                try {Child.StandardInput.WriteLine("openllm-service-stop-v1");Child.StandardInput.Flush();Child.StandardInput.Close();}
                catch(IOException) {} // The child may already have exited.
                if(!Child.WaitForExit(10000)) {
                    // Do not clear the RTC marker here. Only the daemon's exit
                    // hook can attest a graceful shutdown; forced death counts.
                    WriteLog("openllmd.err.log","service-control: graceful stop deadline; terminating owned daemon pid="+Child.Id);
                    ExitCode=1;Child.Kill();Child.WaitForExit(3000);
                } else {
                    WriteLog("openllmd.out.log","service-control: daemon exited pid="+Child.Id+" code="+Child.ExitCode);
                }
            }
        } catch(InvalidOperationException) {}
        Child.Dispose();Child=null;
    }
    protected override void OnShutdown() { OnStop(); }
}
