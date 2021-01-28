FROM alpine:latest

RUN apk --no-cache add openssh-keygen jq openssh-client

COPY --from=hashicorp/terraform:0.14.4 /bin/terraform /bin/terraform

COPY ./terraform /terraform

COPY ./verify/audit.sh /verify/audit.sh

COPY ./entrypoint.sh /bin/entrypoint.sh

ENTRYPOINT [ "/bin/entrypoint.sh" ]
