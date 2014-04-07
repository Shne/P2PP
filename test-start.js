var th = require('telehash');
var fs = require('fs');

var mySeeds = JSON.parse(fs.readFileSync('seeds.json', {encoding:'utf8'}));

th.init({seeds:mySeeds}, function(err, self){
	if(err) return console.log('hashname generation/startup failed',err);
	// console.log(self.id);
	
	self.start("553ce1a43ec9e58561dacef199c741b11000ee0c29185ce861fad13f12453e5c", "derp", {js:{msg:"FFFF"}}, function(err, packet, chan){
		if(err) return console.log('START ERROR: ',err);
		// console.log(packet);
		console.log(chan.inq);
	})
});