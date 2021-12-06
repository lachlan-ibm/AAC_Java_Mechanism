# IBM Security Verify Access AAC Java Extension Authentication Mechanism

## Java Mechanism
The source code and associated build files for the custom java mechanism.

To build this mechanism two jars are required. One is the AAC mechanism extension, which is downloaded from an IBM
Security Verify Access appliance; the second is an implementation of the javax.json interfaces. I used the Webshpere JSON-P
jar but any implementation of the javax.json interface should work.

### Building the mechanism
This project uses the Apache Ant build system. To compile the code use:
```
ant build
```

To package the code into a jar for distribution use:
```
ant dist
```

To remove all build artifacts use:
```
ant clean
```

## Postman Collection
A collection of API requests are also provided to help with the testing of AAC Authentication Mechanisms. This collection 
can be imported into Postman and used to simulate a end user logging into WebSEAL and then completing an authentication
request.
