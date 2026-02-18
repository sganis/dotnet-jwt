# Deploy .NET 9 in IIS

## 0. Install the .NET 9 Windows Hosting Bundle

Download and install on the IIS server:

- URL: https://dotnet.microsoft.com/en-us/download/dotnet/9.0
- File: `dotnet-hosting-9.0.x-win.exe`

This installs the ASP.NET Core Runtime, .NET Runtime, and the IIS ASP.NET Core Module (ANCM).

After installation, restart IIS:

```bash
iisreset
```

## 1. Create a new Application Pool

| Setting               | Value           |
|-----------------------|-----------------|
| Name                  | Api             |
| .NET CLR version      | No Managed Code |
| Managed pipeline mode | Integrated      |

> ANCM handles the runtime — IIS does not need a managed CLR version.

## 2. Create a new Application

Right-click **Default Web Site** (or your target site) in IIS Manager:

| Setting          | Value                |
|------------------|----------------------|
| Alias            | Api                  |
| Application pool | Api                  |
| Physical path    | `C:\inetpub\www\Api` |

If using Windows Authentication, disable Anonymous Auth and enable Windows Auth here.

## 3. Publish

Use the `dotnet publish` CLI (preferred over the Visual Studio publish UI).

**Framework-dependent** — smaller output, requires Hosting Bundle on the server:

```bash
dotnet publish auth/auth.csproj -c Release -f net9.0 -o bin/Release/net9.0/publish
```

**Self-contained** — bundles the runtime, no server-side install needed:

```bash
dotnet publish auth/auth.csproj -c Release -f net9.0 -r win-x64 --self-contained true -o bin/Release/net9.0/publish
```

> **Note:** Do NOT use `--single-file` — IIS does not support single-file deployments.

## 4. Copy output to IIS

```bash
xcopy /E /Y bin\Release\net9.0\publish\* C:\inetpub\www\Api\
```

## 5. Verify web.config

The publish step generates `web.config` automatically. Confirm it is present in `C:\inetpub\www\Api\`.

Framework-dependent:

```xml
<aspNetCore processPath="dotnet" arguments=".\auth.dll" stdoutLogEnabled="false" ... />
```

Self-contained (no `dotnet` prefix):

```xml
<aspNetCore processPath=".\auth.exe" stdoutLogEnabled="false" ... />
```

## 6. Windows Authentication (dotnet-jwt-login only)

In IIS Manager → select the application → **Authentication**:

- Disable: Anonymous Authentication
- Enable: Windows Authentication

Ensure `appsettings.json` has no explicit Kestrel config that would override IIS settings. ANCM passes the Windows identity to ASP.NET Core automatically.

## 7. Permissions

Grant the app pool identity (`IIS AppPool\Api`) **read** access to `C:\inetpub\www\Api\`.

If the app writes logs or files, also grant **write** access to the relevant subdirectory.

## 8. Verify it is running

Browse to `http://localhost/Api/`.

To enable stdout logging for troubleshooting, edit `web.config`:

```xml
stdoutLogEnabled="true" stdoutLogFile=".\logs\stdout"
```

> Create the `logs\` folder manually first — IIS will not create it automatically.

---

## Notes vs. .NET 5 Deployment

| Topic | Change |
|---|---|
| Hosting Bundle URL | `/dotnet/9.0` instead of `/dotnet/5.0` |
| In-process hosting | Now the default (`hostingModel="inprocess"`) — faster than out-of-process |
| Single-file publish | Still unsupported under IIS |
| Framework-dependent | Simpler and smaller when Hosting Bundle is installed |
| Self-contained | Ships the runtime with the app — use when you cannot install the Hosting Bundle |
