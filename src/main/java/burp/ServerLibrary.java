package burp;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;

public interface ServerLibrary extends Library {
    ServerLibrary INSTANCE = Native.load((Platform.isMac() ? "lib" : "") + "server." + (Platform.isWindows() ? "dll" : Platform.isMac() ? "dylib" : "so"), ServerLibrary.class);

    String StartServer(String spoofAddr);

    String StopServer();

    String GetFingerprints();

    /**
     * @return the Go side's own view of its listeners, as JSON. See {@code runtimestatus.go}.
     * Java must not infer any of this; a listener keeps serving on the address it bound to, not
     * the one currently in the settings.
     */
    String GetRuntimeStatus();

    void SmokeTest();
}
