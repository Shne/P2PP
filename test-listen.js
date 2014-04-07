var th = require('telehash');


th.init({}, function(err, self){
	if(err) return console.log('hashname generation/startup failed',err);
	console.log(self.id);
	console.log(self.hashname);

	self.listen("derp", function(err, packet, chan){
		if(err) return console.log('ERROR: ',err);
		console.log(packet);
		console.log(chan);
	})
});