# Función que extrae eventos recientes de los registros de Windows y exporta a CSV
function ExtraccionDeEventos {
    # Define la fecha de inicio (hace 2 días)
    $FechaInicio = (Get-Date).AddDays(-2)

    # Obtiene eventos de Seguridad, Sistema y Aplicación desde esa fecha
    $EventosSeguridad   = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$FechaInicio}
    $EventosSistema     = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$FechaInicio}
    $EventosAplicacion  = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$FechaInicio}

    # Exporta eventos generales a archivos CSV
    $EventosSeguridad   | Select-Object TimeCreated, Id, Message | Export-Csv "EventosSeguridad.csv" -NoTypeInformation
    $EventosSistema     | Select-Object TimeCreated, Id, Message | Export-Csv "EventosSistema.csv" -NoTypeInformation
    $EventosAplicacion  | Select-Object TimeCreated, Id, Message | Export-Csv "EventosAplicacion.csv" -NoTypeInformation

    # Filtra eventos de Seguridad con IDs considerados sospechosos
    $IDsSospechosos = @(4624,4625,4648,4776,4720,4722,4723,4724,4725,4726,4740,4672,4728,4729,4732,4733,4756,4757,4688,4697,4698,4699,4663,5140,5145,1102,4719,7045,5156,5158,4104,1116)
    $EventosSospechosos = $EventosSeguridad | Where-Object { $IDsSospechosos -contains $_.Id }

    # Exporta eventos sospechosos a CSV
    $EventosSospechosos | Select-Object TimeCreated, Id, Message | Export-Csv "EventosSospechosos.csv" -NoTypeInformation

    # Mensaje de finalización y pausa
    Write-Host "Extraccion completada. Archivos CSV generados. Saliendo en 5 segundos al Menu/Continuando con los demas procesos"
    Start-Sleep -Seconds 5
}

# Función que muestra conexiones de red y procesos sin firma válida
function MostrarConexionesYProcesos {
    Write-Host "`nConexiones activas:"
    # Lista conexiones TCP establecidas
    Get-NetTCPConnection -State Established | Select RemoteAddress, RemotePort, OwningProcess | Sort-Object RemotePort

    Write-Host "`nPuertos abiertos:"
    # Lista puertos en estado de escucha
    Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort

    Write-Host "`nProcesos sin firma:"
    # Muestra procesos cuyo ejecutable no tiene firma válida
    Get-Process | Where-Object { $_.Path -and (Get-AuthenticodeSignature $_.Path).Status -ne 'Valid' } | Select Name, Id, Path
}

# Función que investiga la reputación de direcciones IP públicas
function InvestigacionDeDireccionesIP {
    param (
        [string]$ClaveAPI = "bbe5808fcade32b504a1508b6cdc2112fd36b86e11b4ee5cd8b71938d999592d0d018df932029845",
        [string]$EntradaDeIPs = ""
    )

    # Si no se proporcionan IPs, se detectan automáticamente desde conexiones activas
    if ([string]::IsNullOrWhiteSpace($EntradaDeIPs)) {
        Write-Host "`nNo se proporcionaron IPs manuales. Extrayendo IPs activas del sistema..."
        $IPsDetectadas = @()
        $Conexiones = Get-NetTCPConnection -State Established | Select-Object -ExpandProperty RemoteAddress

        # Filtra IPs públicas (excluye rangos privados)
        foreach ($IP in $Conexiones) {
            if ($IP -match '\b(?:\d{1,3}\.){3}\d{1,3}\b' -and
                $IP -notmatch '^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.|^127\.') {
                $IPsDetectadas += $IP
            }
        }
        $ListaDeIPs = $IPsDetectadas | Sort-Object -Unique
    } else {
        # Procesa IPs ingresadas manualmente
        $ListaDeIPs = $EntradaDeIPs -split "," | ForEach-Object { $_.Trim() }
        $ListaDeIPs = $ListaDeIPs | Where-Object {
            ($_ -match '\b(?:\d{1,3}\.){3}\d{1,3}\b') -and
            ($_ -notmatch '^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.|^127\.')
        } | Sort-Object -Unique
    }

    # Función interna para consultar reputación de IP en AbuseIPDB
    function ObtenerReputacionIP {
        param ([string]$IP)
        $URL = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90"
        $Encabezados = @{
            "Key" = $ClaveAPI
            "Accept" = "application/json"
        }

        try {
            $Respuesta = Invoke-RestMethod -Uri $URL -Method Get -Headers $Encabezados
            return $Respuesta.data
        } catch {
            Write-Host "Error al consultar la IP $IP"
            return $null
        }
    }

    # Consulta y clasifica cada IP según su puntaje de abuso
    foreach ($IP in $ListaDeIPs) {
        $Informacion = ObtenerReputacionIP -IP $IP
        if ($Informacion) {
            $Puntaje = $Informacion.abuseConfidenceScore
            $Clasificacion = if ($Puntaje -ge 80) { "Alto riesgo" } elseif ($Puntaje -ge 40) { "Riesgo medio" } else { "Bajo riesgo" }
            Write-Host "IP: $IP | Puntaje: $Puntaje | Clasificacion: $Clasificacion"
        }
    }

    # Pausa para que el usuario revise resultados
    Read-Host "Presiona Enter para continuar..."
}


