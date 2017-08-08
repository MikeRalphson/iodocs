#!/bin/env node

var fs = require('fs');
var sass = require('node-sass');

var outputStyle = process.argv.length > 2 ? process.argv[2] : 'nested';

function sassRender(infile,outfile) {
	sass.render({
		file: infile,
		outputStyle : outputStyle,
	}, function(err, result) { 
		if (err) console.error(err)
		else {
			fs.writeFile(outfile,result.css.toString(),'utf8');
   		}
	});
}

sassRender('./public/stylesheets/scss/style.scss','./public/stylesheets/style.css');
