"""Runs dedicated native fixtures. Never targets Explorer or installed MyWallpaper."""
import argparse, ctypes, hashlib, json, os, pathlib, queue, shutil, struct, subprocess, threading, time, uuid
from ctypes import wintypes
K = ctypes.WinDLL("kernel32", use_last_error=True)
K.CreateEventW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.BOOL,wintypes.LPCWSTR]; K.CreateEventW.restype=wintypes.HANDLE
K.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; K.OpenProcess.restype=wintypes.HANDLE
K.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
K.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT]
K.CloseHandle.argtypes=[wintypes.HANDLE]
K.SetEvent.argtypes=[wintypes.HANDLE]
K.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]; K.WaitForSingleObject.restype=wintypes.DWORD
K.PeekNamedPipe.argtypes=[wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
K.WaitNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD]
PSAPI = ctypes.WinDLL("psapi",use_last_error=True)
class Counters(ctypes.Structure):
    _fields_=[("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD)]+[(n,ctypes.c_size_t) for n in
        ["PeakWorkingSetSize","WorkingSetSize","QuotaPeakPagedPoolUsage","QuotaPagedPoolUsage",
         "QuotaPeakNonPagedPoolUsage","QuotaNonPagedPoolUsage","PagefileUsage","PeakPagefileUsage","PrivateUsage"]]
PSAPI.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
def memory(pid):
    handle=K.OpenProcess(0x1000,False,pid)
    if not handle: raise ctypes.WinError(ctypes.get_last_error())
    try:
        counters=Counters(); counters.cb=ctypes.sizeof(counters)
        if not PSAPI.GetProcessMemoryInfo(handle,ctypes.byref(counters),counters.cb): raise ctypes.WinError(ctypes.get_last_error())
        return counters.PrivateUsage
    finally: K.CloseHandle(handle)
def wait_for(predicate, description, timeout=12):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        result=predicate()
        if result:return result
        time.sleep(.025)
    raise AssertionError("timeout: "+description)
def stop_owned_fixture(pid,expected_image):
    # Keep the checked process handle through termination: PID reuse cannot
    # redirect cleanup to an unrelated process.
    handle=K.OpenProcess(1|0x1000|0x100000,False,pid)
    if not handle:return
    try:
        name=ctypes.create_unicode_buffer(32768);length=wintypes.DWORD(len(name))
        if not K.QueryFullProcessImageNameW(handle,0,name,ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        assert os.path.normcase(os.path.realpath(name.value))==os.path.normcase(os.path.realpath(expected_image))
        K.TerminateProcess(handle,0);K.WaitForSingleObject(handle,3000)
    finally:K.CloseHandle(handle)
class Pipe:
    def __init__(self,name):
        import msvcrt
        end=time.monotonic()+10
        while True:
            try:self.file=open(name,"r+b",buffering=0);break
            except OSError:
                if time.monotonic()>end:raise
                K.WaitNamedPipeW(name,100)
                time.sleep(.01)
        self.handle=msvcrt.get_osfhandle(self.file.fileno())
    def call(self,value):
        self.file.write(json.dumps(value).encode()+b"\n")
        line=bytearray(); end=time.monotonic()+12
        while not line.endswith(b"\n"):
            available=wintypes.DWORD()
            if not K.PeekNamedPipe(self.handle,None,0,None,ctypes.byref(available),None):raise ctypes.WinError(ctypes.get_last_error())
            if available.value:line.extend(self.file.read(1))
            elif time.monotonic()>end:raise AssertionError("native pipe timed out")
            else:time.sleep(.001)
        return json.loads(line)
    def close(self):self.file.close()
class Fixture:
    def __init__(self,bin_directory):
        self.pipe=r"\\.\pipe\mw-foundation-"+uuid.uuid4().hex
        self.process=subprocess.Popen([str(bin_directory/"mw-native-fixture.exe"),"--pipe",self.pipe,"--workers","0"],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000000)
        ready=json.loads(self.process.stdout.readline());assert ready["entryValue"]==10
    def sample(self):
        pipe=Pipe(self.pipe)
        try:return pipe.call({"id":1,"operation":"sample"})
        finally:pipe.close()
    def stop(self):
        if self.process.poll() is None:
            self.process.terminate();self.process.wait(10)
class Companion:
    def __init__(self,exe,bundle,settings,identifier,scratch,architecture="windows-x86_64"):
        self.process=subprocess.Popen([str(exe),"--bundle",str(bundle)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,creationflags=0x08000000)
        self.output=queue.Queue();self.errors=[]
        def exact(count):
            data=bytearray()
            while len(data)<count:
                chunk=self.process.stdout.read(count-len(data))
                if not chunk:raise EOFError("companion stdout closed")
                data.extend(chunk)
            return data
        def read():
            try:
                while True:
                    raw,=struct.unpack("<I",exact(4));assert raw>>30==0
                    self.output.put(json.loads(exact(raw & 0x3fffffff)))
            except Exception as e:self.output.put(e)
        def errors():
            for line in iter(self.process.stderr.readline,b""): self.errors.append(line.decode(errors="replace"))
        threading.Thread(target=read,daemon=True).start();threading.Thread(target=errors,daemon=True).start()
        self.send({"type":"init","v":5,"addonId":identifier,"artifactDigest":"sha256:"+hashlib.sha256(b"test-artifact").hexdigest(),
            "version":"0.2.0","targetArchitecture":architecture,"scratchDirectory":str(scratch),
            "layerSettings":{},"deviceSettings":settings})
    def send(self,value):
        data=json.dumps(value).encode();self.process.stdin.write(struct.pack("<I",len(data))+data);self.process.stdin.flush()
    def ready(self,timeout=15):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            frame=self.output.get(timeout=max(.01,end-time.monotonic()))
            if isinstance(frame,Exception):raise AssertionError(str(frame)+" "+"".join(self.errors))
            if frame["type"]=="error":raise AssertionError(frame)
            if frame["type"]=="ready":return
        raise AssertionError("companion not ready")
    def stop(self):
        if self.process.poll() is None:
            self.send({"type":"shutdown","v":5});self.process.wait(15)
        assert self.process.returncode==0,"".join(self.errors)
    def kill(self):
        if self.process.poll() is None:self.process.kill();self.process.wait(10)
def descriptor(path,engine,addon,matching="single",launch=None):
    path.mkdir(parents=True,exist_ok=True);shutil.copyfile(addon,path/"addon.dll")
    value={"schemaVersion":2,"addon":{"library":"addon.dll"},"agent":"mw-native-agent.dll",
        "engineDirectory":str(engine),"symbols":{"cacheDirectory":str(engine.parent/"shared-symbols")},
        "target":{"imageName":"mw-native-fixture.exe","match":matching}}
    if launch:value["launch"]=launch
    (path/"mywallpaper-native-engine.json").write_text(json.dumps(value),encoding="utf-8")
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--build",type=pathlib.Path,required=True)
    parser.add_argument("--companion",type=pathlib.Path,required=True)
    parser.add_argument("--architecture",choices=["x64","x86","arm64"],default="x64")
    parser.add_argument("--x86-build",type=pathlib.Path)
    parser.add_argument("--x86-companion",type=pathlib.Path);args=parser.parse_args()
    root=args.build/(".foundation-"+uuid.uuid4().hex);root.mkdir()
    runtime=root/"runtime";(runtime/args.architecture).mkdir(parents=True)
    shutil.copyfile(args.companion,runtime/args.architecture/"companion.exe")
    shutil.copyfile(args.build/"bin"/"mw-native-agent.dll",runtime/args.architecture/"mw-native-agent.dll")
    companion=runtime/args.architecture/"companion.exe";multi=args.build/"bin"/"mw-native-instance-fixture.dll"
    processes=[];fixtures=[];events=[];results={};owned_ready=None;owned_image=None
    def tracked(*arguments,**kwargs):
        if len(arguments)<6:kwargs.setdefault("architecture",{"x64":"windows-x86_64","x86":"windows-x86","arm64":"windows-arm64"}[args.architecture])
        c=Companion(*arguments,**kwargs);processes.append(c);return c
    try:
        # Exact lookup, missing name, and a warm offline cache.
        cache=root/"symbols";module=args.build/"bin"/"mw-native-fixture.exe"
        cli=[str(companion),"symbol","--module",str(module),"--name","MwFixturePrivateCompute","--cache",str(cache)]
        cold=json.loads(subprocess.check_output(cli));warm=json.loads(subprocess.check_output(cli+["--search-path",""]))
        assert not cold["cacheHit"] and warm["cacheHit"] and cold["rva"]==warm["rva"]
        missing=subprocess.run([str(companion),"symbol","--module",str(module),"--name","NoSuchPrivateFunction","--cache",str(cache)],
            capture_output=True,timeout=15);assert missing.returncode!=0
        results["symbols"]={"exactPrivateRva":cold["rva"],"warmCacheHit":True,"missingExactNameRejected":True}

        # A direct native session qualifies identity rejection and bounded reuse.
        fixture=Fixture(args.build/"bin");fixtures.append(fixture)
        target=json.loads(subprocess.check_output([str(companion),"identity","--pid",str(fixture.process.pid)]))
        owner=json.loads(subprocess.check_output([str(companion),"identity","--pid",str(os.getpid())]))
        name=r"\\.\pipe\mw-direct-"+uuid.uuid4().hex
        subprocess.check_output([str(companion),"inject","--pid",str(target["pid"]),"--creation-time",str(target["creationTime"]),
            "--agent",str(runtime/args.architecture/"mw-native-agent.dll"),"--pipe",name,
            "--owner-pid",str(owner["pid"]),"--owner-creation-time",str(owner["creationTime"])],timeout=15)
        pipe=Pipe(name);request_id=0
        def native(operation,**fields):
            nonlocal request_id
            request_id+=1;return pipe.call({"id":request_id,"operation":operation,"addonId":"direct-private",**fields})
        try:
            response=native("load",path=str(multi),settings={"deviceSettings":{"target":"private","delta":7}})
            assert response["code"]==11,response
            request=response["addons"][0]["pendingSymbols"][0];prepared={**request,"rva":cold["rva"]}
            rejected=native("prepareSymbols",symbols=[{**prepared,"pdbAge":request["pdbAge"]+1}]);assert rejected["code"]==3
            assert native("prepareSymbols",symbols=[prepared])["ok"]
            assert native("activate")["ok"]
            sample=fixture.sample();assert sample["privateValue"]==37 and not sample["privateExportVisible"]
            assert native("stop")["ok"];assert fixture.sample()["privateValue"]==30
            for _ in range(100):assert native("activate")["ok"] and native("stop")["ok"]
            baseline=memory(target["pid"]);before=native("status")
            start=time.monotonic()
            for _ in range(1000):assert native("activate")["ok"] and native("stop")["ok"]
            after=native("status");final=memory(target["pid"])
            assert before["backend"]["retainedHookRecords"]==after["backend"]["retainedHookRecords"]==1
            assert before["backend"]["trampolineRegionBytes"]==after["backend"]["trampolineRegionBytes"]
            assert final-baseline<2*1024*1024
            results["reuse"]={"cycles":1000,"seconds":round(time.monotonic()-start,3),"privateBytesBefore":baseline,
                "privateBytesAfter":final,"retainedHookRecords":after["backend"]["retainedHookRecords"],
                "trampolineRegionBytes":after["backend"]["trampolineRegionBytes"],"mismatchedPdbRejected":True}
            assert native("shutdown")["ok"]
        finally:pipe.close()
        fixture.stop()

        # Same physical DLL, independent contexts. A stuck callback cannot block
        # an unrelated instance; owner loss disables hooks before it returns.
        fixture=Fixture(args.build/"bin");fixtures.append(fixture)
        a=root/"addon-a";b=root/"addon-b";descriptor(a,runtime,multi);descriptor(b,runtime,multi)
        first=tracked(companion,a,{"target":"compute","delta":3},"context-a",root/"scratch-a");first.ready()
        second=tracked(companion,b,{"target":"secondary","delta":4},"context-b",root/"scratch-b");second.ready()
        wait_for(lambda:fixture.sample()["value"]==13 and fixture.sample()["secondaryValue"]==24,"two contexts")
        # A late optional lookup is prepared without restarting this active
        # context. The pending settings remain rejected until explicitly retried.
        optional={"type":"settings","v":5,"layerSettings":{},"deviceSettings":{"target":"compute","delta":7,"resolvePrivate":True}}
        first.send(optional)
        wait_for(lambda:any("returned 11" in e for e in first.errors),"pending symbol settings rejection")
        assert fixture.sample()["value"]==13
        def retry_optional():
            first.send(optional)
            return fixture.sample()["value"]==17
        wait_for(retry_optional,"late symbol lookup without reactivation")
        event_name="Local\\mw-foundation-"+uuid.uuid4().hex
        release=K.CreateEventW(None,True,False,event_name);entered=K.CreateEventW(None,True,False,event_name+"-entered")
        events.extend([release,entered])
        first.send({"type":"settings","v":5,"layerSettings":{},"deviceSettings":{"target":"compute","delta":8,"blockEvent":event_name}})
        assert K.WaitForSingleObject(entered,3000)==0
        started=time.monotonic()
        second.send({"type":"settings","v":5,"layerSettings":{},"deviceSettings":{"target":"secondary","delta":6}})
        wait_for(lambda:fixture.sample()["secondaryValue"]==26,"other callback completes",timeout=3)
        other_latency=time.monotonic()-started
        first.kill()
        wait_for(lambda:fixture.sample()["value"]==10 and fixture.sample()["secondaryValue"]==26,"owner-death bypass while callback blocked",timeout=3)
        K.SetEvent(release);time.sleep(.1);second.stop()
        assert fixture.sample()["secondaryValue"]==20
        results["instances"]={"sameDllMultipleContexts":True,"otherCallbackSeconds":round(other_latency,3),
            "ownerDeathBypassesBlockedCallback":True,"stopRestoresBothEffects":True,"lateSymbolsPreparedWhileActive":True}
        # Successful start without hooks must still release its own resources
        # when the owner disappears while that callback is running.
        startup_gate="Local\\mw-startup-"+uuid.uuid4().hex
        startup_release=K.CreateEventW(None,True,False,startup_gate)
        startup_entered=K.CreateEventW(None,True,False,startup_gate+"-entered")
        resource_name="Local\\mw-resource-"+uuid.uuid4().hex
        resource=K.CreateEventW(None,True,False,resource_name)
        events.extend([startup_release,startup_entered,resource])
        no_hooks=tracked(companion,a,{"noHooks":True,"resourceEvent":resource_name,"startBlockEvent":startup_gate},
            "no-hooks-context",root/"scratch-no-hooks")
        assert K.WaitForSingleObject(startup_entered,3000)==0
        assert K.WaitForSingleObject(resource,0)==0
        no_hooks.kill();K.SetEvent(startup_release)
        wait_for(lambda:K.WaitForSingleObject(resource,0)==258,"owner death cleans non-hook startup resources")
        results["instances"]["ownerDeathCleansNoHookStartup"]=True
        fixture.stop()

        # Common manager follows all matching processes, then restarts them and
        # reapplies only the last accepted settings.
        one=Fixture(args.build/"bin");two=Fixture(args.build/"bin");fixtures.extend([one,two])
        bundle=root/"addon-all";descriptor(bundle,runtime,multi,matching="all")
        all_targets=tracked(companion,bundle,{"target":"compute","delta":2},"all-contexts",root/"scratch-all");all_targets.ready()
        wait_for(lambda:one.sample()["value"]==12 and two.sample()["value"]==12,"all matching processes")
        all_targets.send({"type":"settings","v":5,"layerSettings":{},"deviceSettings":{"target":"compute","delta":5}})
        wait_for(lambda:one.sample()["value"]==15 and two.sample()["value"]==15,"accepted settings")
        all_targets.send({"type":"settings","v":5,"layerSettings":{},"deviceSettings":{"target":"compute","delta":99,"reject":True}})
        time.sleep(.1);one.stop();two.stop()
        replacement=Fixture(args.build/"bin");fixtures.append(replacement)
        wait_for(lambda:replacement.sample()["value"]==15,"restart receives accepted snapshot")
        all_targets.stop();assert replacement.sample()["value"]==10;replacement.stop()
        results["targets"]={"multipleProcesses":True,"reconnectAfterRestart":True,"rejectedSnapshotNotReplayed":True}

        # A 64-bit companion delegates only injection to a 32-bit helper. The
        # original companion must remain the owner after that helper exits.
        if args.architecture=="x64" and args.x86_build and args.x86_companion:
            (runtime/"x86").mkdir()
            shutil.copyfile(args.x86_companion,runtime/"x86"/"companion.exe")
            shutil.copyfile(args.x86_build/"bin"/"mw-native-agent.dll",runtime/"x86"/"mw-native-agent.dll")
            fixture32=Fixture(args.x86_build/"bin");fixtures.append(fixture32)
            bundle32=root/"addon-x86"
            descriptor(bundle32,runtime,args.x86_build/"bin"/"mw-native-instance-fixture.dll")
            cross=tracked(companion,bundle32,{"target":"compute","delta":6},"cross-context",root/"scratch-cross","windows-x86")
            cross.ready();time.sleep(.2)
            assert fixture32.sample()["value"]==16
            cross.kill()
            wait_for(lambda:fixture32.sample()["value"]==10,"original 64-bit owner cleanup",timeout=3)
            fixture32.stop()
            results["crossArchitecture"]={"x64CompanionToX86Target":True,"helperExitPreservesEffects":True,"originalOwnerDeathRestoresEffect":True}

        # Owned application launch: the first call in wmain is already hooked.
        early_bundle=root/"addon-early";ready=root/"entry-ready.json"
        owned_ready=ready;owned_image=module
        external=Fixture(args.build/"bin");fixtures.append(external)
        suffix=r"\\.\pipe\mw-early-"+uuid.uuid4().hex
        descriptor(early_bundle,runtime,multi,launch={"executable":str(module),
            "arguments":["--pipe",suffix,"--workers","0","--ready-file",str(ready)]})
        early=tracked(companion,early_bundle,{"target":"compute","delta":9},"early-context",root/"scratch-early")
        early.ready(25);wait_for(lambda:ready.is_file() and ready.stat().st_size>0,"entry evidence")
        entry=json.loads(ready.read_text());assert entry["entryValue"]==19,entry
        time.sleep(.6)
        assert early.process.poll() is None and external.sample()["value"]==10
        early.stop()
        client=Pipe(suffix)
        try:assert client.call({"id":1,"operation":"sample"})["value"]==10
        finally:client.close()
        stop_owned_fixture(entry["pid"],module);owned_ready=None
        external.stop()
        results["earlyLaunch"]={"firstCallAlreadyHooked":True,"entryValue":entry["entryValue"],"stopRestoresEffect":True,"onlyOwnedChildModified":True}
        print(json.dumps({"passed":True,**results},indent=2))
    finally:
        for event in events:
            K.SetEvent(event);K.CloseHandle(event)
        for process in processes:process.kill()
        for fixture in fixtures:fixture.stop()
        if owned_ready and owned_ready.is_file():
            stop_owned_fixture(json.loads(owned_ready.read_text())["pid"],owned_image)
if __name__=="__main__":main()
