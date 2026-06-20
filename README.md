# Zero-Trust-Architecture

This is the very short description that I wrote while falling asleep (just for fun).
<br/>
The repo is a microservice backend application, written in Go and consists of 3 main application:
1. PEP: Acts as the router for requests coming from external clients. In this case, it can be treated as an API gateway and load balancer, although its role as a load balancer is not fully structured to be considered mature.
2. PDP:
- Acts as the credentials validator and token retention center. It validates the credentials packed in the request payload by 2 ways:
  - Check the authorization header
  - Check payload parameters
- After validating the credentials, the machine's metadata (also packed in the request) will be checked in case if there are any failures.
<br/>
(It is highly recommened to have a Connector implemented for integration in real life)
3. Backend: A simple backend application consisting of controllers and related endpoints. The data will be returned based on request extracted from external clients.
<br/>
Also, the demo script is already prepared so that developers can test the flow and see how does this work. A simple logging syster is also implemented to help developers keep track with the flow. 
