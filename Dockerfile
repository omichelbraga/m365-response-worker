# PowerShell 7.4 LTS on Ubuntu 22.04.
# Pinned deliberately: .NET 9 marks the X509Certificate2 file constructor obsolete,
# and actions.ps1 relies on it to load the PFX at runtime.
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

ENV WORKER_PORT=8080 \
    EXO_CERT_PATH=/certs/exo.pfx \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

# 3.9.0+ is required for New-ComplianceSearchAction purge support.
RUN pwsh -NoLogo -NonInteractive -Command " \
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
      Install-Module -Name ExchangeOnlineManagement -MinimumVersion 3.9.0 -Scope AllUsers -Force; \
      Get-Module -ListAvailable ExchangeOnlineManagement | Select-Object Name,Version"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10002 worker \
    && mkdir -p /certs \
    && chown worker:worker /certs

COPY --chown=worker:worker src/ /app/

USER 10002
WORKDIR /app

EXPOSE 8080

CMD ["pwsh", "-NoLogo", "-NonInteractive", "-File", "/app/server.ps1"]
