# Collaborator Everywhere

- This is alternative of Collaborator-Everywhere by Portswigger [https://github.com/PortSwigger/collaborator-everywhere, since that one is old and some broken functionality.
- I have created same extension with montoya-2025.5 version, and added some UI and feture to identity the injection point when interaction is happened.

## Installation 
- directly download the Jar file from the release and add to burpsuite via Extention > add > java > collaborator-everywhere-1.1.jar

## To build 
- clone the repo `github.com/DK9510/collaborator-everywhere/.git `
- Download mevan ( mvn) for ubuntu.
- go to collaborator-everywhere : `cd collaborator-everywhere/`
  ```
  mvn clean package
  ```

- The genarated jar file is at `collaborator-everywhere/target/jar-file`

## currrent features
- extension only work of the scoped request, if url is not is scope the extension will not add collaborator payloads or headers.
- when traffic came throgh Proxy : it will add custom headers like x-client-id, x-forwarded-for etc to see if there is any hidden endpoint for ssrf, redirect
- when use scanner it will automatically  add headers as well as some parameters like url, source,src, etc

eg. Images.
1. Log request how it looks like when request is modified by the extension.
![image](https://github.com/user-attachments/assets/11e267d9-d671-431e-a969-23edead65abc)

2. UI for interaction logs, you can copy nonce id and search in the Logger for whole injected request.
![image](https://github.com/user-attachments/assets/bcae6492-681f-4178-8fdf-38ac6bbdf6ee)
