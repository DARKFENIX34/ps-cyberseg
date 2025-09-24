# ps-cyberseg

# Editado por RENE VILLARREAL TORRES el 23/09/2025

¿Qué contiene?
El proyecto contiene dos módulos principales de PowerShell:

Módulo de Seguridad de Eventos

SeguridadEventos.psm1 → Módulo principal con 3 funciones de seguridad

SeguridadEventosMANIFIESTO.psd1 → Manifiesto del módulo

MenuSeguridad.ps1 → Script de menú interactivo

Módulo de Auditoría Básica

AuditoriaBasica.psm1 → Funciones de auditoría de usuarios y servicios

AuditoriaBasica.psd1 → Manifiesto del módulo

script-principal.ps1 → Script independiente de auditoría

¿Qué scripts se incluyen?

Scripts ejecutables principales

MenuSeguridad.ps1 → Menú interactivo con 4 opciones de seguridad

script-principal.ps1 → Script de auditoría básica con 2 opciones

Módulos de funciones

SeguridadEventos.psm1 → Contiene 3 funciones principales de seguridad

AuditoriaBasica.psm1 → Contiene 2 funciones de auditoría

¿Qué tareas de ciberseguridad resuelven?

Análisis Forense y Monitoreo

Extracción automatizada de eventos de Windows (Security, System, Application)

Detección de eventos sospechosos mediante 32 IDs predefinidos

Generación de reportes CSV para análisis forense

Monitoreo de Red en Tiempo Real

Análisis de conexiones activas TCP establecidas y en escucha

Detección de procesos sin firma digital válida

Identificación de puertos abiertos y procesos asociados

Inteligencia de Amenazas Externa

Consulta de reputación de IPs usando API de AbuseIPDB

Clasificación automática de riesgo (alto, medio, bajo)

Detección inteligente de IPs públicas en conexiones activas

Auditoría de Seguridad del Sistema

Identificación de usuarios inactivos pero habilitados

Detección de servicios de terceros en ejecución

Generación de reportes en formatos CSV y HTML

¿Qué aprendiste al desarrollarlos?

Técnicas Avanzadas de PowerShell

Creación y gestión de módulos con manifiestos

Filtrado avanzado con Where-Object y FilterHashtable

Consultas a APIs REST con autenticación por headers

Manipulación de fechas para periodos personalizados

Conceptos de Ciberseguridad Aplicada

Significado de IDs de eventos críticos en Windows Security Log

Diferenciación entre IPs públicas y privadas usando regex

Interpretación de puntajes de reputación de AbuseIPDB

Análisis de firmas digitales en archivos ejecutables

Buenas Prácticas de Desarrollo

Diseño modular para reutilización de código

Interfaces de usuario intuitivas con menús interactivos

Manejo robusto de errores en consultas externas

Documentación integrada con comentarios help

Lecciones de Seguridad Operacional

Automatización de tareas repetitivas de monitoreo

Integración de múltiples fuentes (logs locales + inteligencia externa)

Priorización de alertas basada en niveles de riesgo cuantificables

Exportación estandarizada de datos para análisis posterior
