Using Telehash http://telehash.org/  
https://github.com/telehash/node-telehash  
https://github.com/telehash/thjs  


HOWTO (Ubuntu)
--------
First make sure you don't have gyp installed already from repositories 
`sudo apt-get purge gyp`

**Installing**  
install node js from http://nodejs.org/ (not from repos)  
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
copy-paste the outputted hashname and insert it into the test-start.js file where there's currently another hashname  

In another terminal:
```
node test-start.js
```
both terminals should now spam you. what you're looking for is the first lines which should be `[ { js: { msg: "FFFF" },` and `[ { js: { msg: "HURRR" },` respectively.
