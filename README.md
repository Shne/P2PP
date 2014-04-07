Using Telehash http://telehash.org/  
https://github.com/telehash/node-telehash  
https://github.com/telehash/thjs  


HOWTO
--------
install node js from http://nodejs.org/ (not from repos)  


**Installing**
```
npm install telehash
```
**Running your own seed (required)**
```
cd node_modules/telehash
npm start
```
Take the json object from the output and save it as seeds.json in the root folder

**Running the test**  
In root folder:
```
node test-listen.js
```
In another terminal:
```
node test-start.js
```
