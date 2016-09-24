var fs = require('fs');
var path = require('path');

function iodocsUpgrade(filename){
	console.log('Updating: %s',filename);
	var data = require(path.resolve(filename));
	var data = data['endpoints'];
	var newResource = {};
	newResource.resources = {};
	for (var index2 = 0; index2 < data.length; index2++) {
		var resource = data[index2];
		var resourceName = resource.name;
		newResource.resources[resourceName] = {};
		newResource.resources[resourceName].methods = {};
		var methods = resource.methods;
		for (var index3 = 0; index3 < methods.length; index3++) {
			var method = methods[index3];
			var methodName = method['MethodName'];
			var methodName = methodName.split(' ').join('_');
			newResource.resources[resourceName].methods[methodName] = {};
			newResource.resources[resourceName].methods[methodName].name = method['MethodName'];
			newResource.resources[resourceName].methods[methodName]['httpMethod'] = method['HTTPMethod'];
			newResource.resources[resourceName].methods[methodName]['path'] = method['URI'];
			newResource.resources[resourceName].methods[methodName].parameters = {};
			if (!method.parameters) {
				continue;
			}
			var parameters = method.parameters;
			for (var index4 = 0; index4 < parameters.length; index4++) {
				var param = parameters[index4];
				newResource.resources[resourceName].methods[methodName].parameters[param.Name] = {};
				newResource.resources[resourceName].methods[methodName].parameters[param.Name]['title'] = param.name;
				newResource.resources[resourceName].methods[methodName].parameters[param.Name]['required'] = (param['Required'] == 'Y');
				newResource.resources[resourceName].methods[methodName].parameters[param.Name]['default'] = param['Default'];
				newResource.resources[resourceName].methods[methodName].parameters[param.Name]['type'] = param['Type'];
				newResource.resources[resourceName].methods[methodName].parameters[param.Name]['description'] = param['Description'];
			}
		}
	}
	fs.writeFileSync(filename.replace('.json','_new.json'),JSON.stringify(newResource,null,2),'utf8');
}

module.exports = {

	iodocsUpgrade : iodocsUpgrade

};

if (process.argv.length>2) {
	iodocsUpgrade(process.argv[2]);
}
else {
	console.log('Usage: convert_iodocs {inputfile}')
}
