var fs = require('fs');
var path = require('path');

var converters = require('./converters.js');

function iodocsUpgradeFile(filename){
	console.log('Updating: %s',filename);
	var data = require(path.resolve(filename));
    var newResource = converters.iodocsUpgrade(data);
	fs.writeFileSync(filename.replace('.json','_new.json'),JSON.stringify(newResource,null,2),'utf8');
}

module.exports = {

    iodocsUpgradeFile : iodocsUpgradeFile

};

if (process.argv.length>2) {
	iodocsUpgradeFile(process.argv[2]);
}
else {
	console.log('Usage: convert_iodocs {inputfile}')
}