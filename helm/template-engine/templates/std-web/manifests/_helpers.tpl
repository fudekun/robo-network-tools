{{/*
Return the proper stdWeb image name
*/}}
{{- define "stdWeb.image" -}}
{{- include "common.images.image" (dict "imageRoot" .Values.stdWeb.di.deployment.image "global" .Values.stdWeb.di.deployment.global) -}}
{{- end -}}

{{/*
Return the proper Docker Image Registry Secret Names
*/}}
{{- define "stdWeb.imagePullSecrets" -}}
{{- include "common.images.pullSecrets" (dict "images" (list .Values.stdWeb.di.deployment.image) "global" .Values.stdWeb.di.deployment.global) -}}
{{- end -}}

{{/*
Return  the proper Storage Class
*/}}
{{- define "stdWeb.storageClass" -}}
{{- include "common.storage.class" (dict "persistence" .Values.stdWeb.di.deployment.persistence "global" .Values.stdWeb.di.deployment.global) -}}
{{- end -}}

{{/*
 Create the name of the service account to use
 */}}
{{- define "stdWeb.serviceAccountName" -}}
{{- if .Values.stdWeb.di.serviceAccount.create -}}
    {{- default (include "common.names.fullname" .) .Values.stdWeb.di.serviceAccount.name -}}
{{- else -}}
    {{- default "default" .Values.stdWeb.di.serviceAccount.name -}}
{{- end -}}
{{- end -}}