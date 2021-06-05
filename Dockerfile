FROM alpine:latest

RUN apk --no-cache add openssh-keygen jq openssh-client

COPY --from=hashicorp/terraform:0.15.0 /bin/terraform /bin/terraform

COPY ./terraform /terraform

COPY ./verify/ /verify/

COPY ./entrypoint.sh /bin/entrypoint.sh

ENTRYPOINT [ "/bin/entrypoint.sh" ]
