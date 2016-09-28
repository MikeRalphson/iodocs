var url = require('url');
var clone = require('clone');

var recurseotron = require('openapi_optimise/common.js');

function rename(obj,key,newKey){
    obj[newKey] = obj[key];
    delete obj[key];
}

function fixPathParameters(s){
    if (!s.startsWith('/')) s = '/'+s;
    s = s + '/';
    s = s.replace(/:(.+?)([\.\/:\{&])/g,function(match,group1,group2){
        group1 = '{'+group1.replace(':','')+'}';
        return group1+group2;
    });
    s = s.substr(0,s.length-1);
    return s;
}

/**
* Convert pre-Summer 2014 iodocs format to latest schema. Originally based on python code by https://github.com/hskrasek
*/

function iodocsUpgrade(data){
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
    return newResource;
}

/**
* function to reformat swagger paths object into an iodocs-style resources object
* this is purely to render the schema, but could be the start of a spec converter if needed
* auth is handled server side TODO check client-side knows auth requirements
*/
function convertSwagger(apiInfo){
    apiInfo.resources = {};
    for (var p in apiInfo.paths) {
        for (var m in apiInfo.paths[p]) {
            var sMethod = apiInfo.paths[p][m];
            var ioMethod = {};
            ioMethod.httpMethod = m.toUpperCase();
            var sMethodUniqueName = sMethod.operationId ? sMethod.operationId : m+'_'+p;
            sMethodUniqueName = sMethodUniqueName.split(' ').join('_');
            ioMethod.name = sMethodUniqueName;
            ioMethod.summary = sMethod.summary;
            ioMethod.description = sMethod.description;
            ioMethod.parameters = {};
            for (var p2 in sMethod.parameters) {
                var param = sMethod.parameters[p2];
                param.location = param["in"];
                delete param["in"];
                ioMethod.parameters[param.name] = param;
            }
            ioMethod.path = p;
            var tagName = 'Default';
            if (sMethod.tags && sMethod.tags.length>0) {
                tagName = sMethod.tags[0];
            }
            if (!apiInfo.resources[tagName]) {
                apiInfo.resources[tagName] = {};
                if (apiInfo.tags) {
                    for (var t in apiInfo.tags) {
                        var tag = apiInfo.tags[t];
                        if (tag.name == tagName) {
                            apiInfo.resources[tagName].description = tag.description;
                            apiInfo.resources[tagName].externalDocs = tag.externalDocs;
                        }
                    }
                }
            }
            if (!apiInfo.resources[tagName].methods) apiInfo.resources[tagName].methods = {};
            apiInfo.resources[tagName].methods[sMethodUniqueName] = ioMethod;
        }
    }
    delete apiInfo.paths; // to keep size down
    rename(apiInfo,'definitions','schemas');
    return apiInfo;
}

/**
* function to convert LiveDocs spec into modern iodocs format
*/
function convertLiveDocs(apiInfo){
    rename(apiInfo,'title','name');
    rename(apiInfo,'prefix','publicPath');
    rename(apiInfo,'server','basePath');
    apiInfo.resources = {};
    for (var e in apiInfo.endpoints) {
        var ep = apiInfo.endpoints[e];
        var eName = ep.name ? ep.name : 'Default';

        if (!apiInfo.resources[eName]) apiInfo.resources[eName] = {};
        apiInfo.resources[eName].description = ep.description;

        for (var m in ep.methods) {
            var lMethod = ep.methods[m];
            if (!apiInfo.resources[eName].methods) apiInfo.resources[eName].methods = {};
            var mName = lMethod.MethodName ? lMethod.MethodName : 'Default';
            if (mName.endsWith('.')) mName = mName.substr(0,mName.length-1);
            mName = mName.split(' ').join('_');
            rename(lMethod,'HTTPMethod','httpMethod');
            rename(lMethod,'URI','path');
            rename(lMethod,'Synopsis','description');
            rename(lMethod,'MethodName','name');

            lMethod.path = fixPathParameters(lMethod.path);

            var params = {};
            for (var p in lMethod.parameters) {
                var lParam = lMethod.parameters[p];
                if (!lParam.type) lParam.type = 'string';
                if (lParam.type == 'json') lParam.type = 'string';
                if (!lParam.location) {
                    if (lMethod.path.indexOf(':'+lParam.name)>=0) {
                        lParam.location = 'path';
                    }
                    else {
                        lParam.location = 'query';
                    }
                }
                if (lParam.location == 'boddy') lParam.location = 'body'; // ;)
                params[lParam.name] = lParam;
                delete lParam.name;
                delete lParam.input; // TODO checkbox to boolean?
                delete lParam.label;
                rename(lParam,'options','enum');
            }
            lMethod.parameters = params;
            if (Object.keys(params).length==0) delete lMethod.parameters;

            apiInfo.resources[eName].methods[mName] = lMethod;
        }

    }
    delete apiInfo.endpoints; // to keep size down
    return apiInfo;
}

/**
* function to fixup converted iodocs schemas into JSON-schema compatible form
*/
function fixSchema(schema){
    recurseotron.recurse(schema,{},function(obj,state){
        if ((state.key == 'id') && (typeof obj == 'string')) delete state.parent.id;
        if ((state.key == 'title') && (typeof obj == 'string')) delete state.parent.title;
        if ((state.key == 'description') && (typeof obj == 'string')) delete state.parent.description;
        if ((state.key == 'location') && (typeof obj == 'string')) delete state.parent.location;
        if ((state.key == 'type') && (typeof obj == 'string')) {
            if (obj == 'textarea') {
                state.parent.type = 'string';
            }
        }
        if ((state.key == '$ref') && (typeof obj == 'string') && !obj.startsWith('#/')) {
            state.parent["$ref"] = '#/definitions/'+obj;
        }
        if ((state.key == 'required') && (typeof obj == 'boolean')) {
            if (obj === true) {
                var greatgrandparent = state.parents[state.parents.length-3];
                if (greatgrandparent) {
                    if (state.keys[state.keys.length-2] != 'items') { // TODO better check for arrays
                        if (!greatgrandparent.required) greatgrandparent.required = [];
                        greatgrandparent.required.push(state.keys[state.keys.length-2]);
                    }
                }
            }
            delete state.parent.required;
        }
    });
}

/**
* function to convert modern iodocs format to swagger 2.0
*/
function exportIodocs(src){
    var obj = clone(src);
    obj.swagger = '2.0';
    obj.info = {};
    obj.info.version = obj.version || '1';
    obj.info.title = obj.name;
    obj.info.description = obj.description;
    obj.paths = {};

    var u = url.parse(obj.basePath+obj.publicPath);
    obj.schemes = [];
    obj.schemes.push(u.protocol.replace(':',''));
    obj.host = u.host;
    obj.basePath = u.path;

    delete obj.version;
    delete obj.title;
    delete obj.description;
    delete obj.publicPath;
    delete obj.privatePath; // for oauth etc
    delete obj.protocol;
    delete obj.name;
    delete obj.auth; // TODO
    delete obj.oauth; // TODO
    delete obj.headers; // TODO
    rename(obj,'schemas','definitions');
    if (obj.definitions) fixSchema(obj.definitions);

    for (var r in obj.resources) {
        var resource = obj.resources[r];
        // do tags
        for (var m in resource.methods) {
            var method = resource.methods[m];

            method.path = fixPathParameters(method.path);

            if (!obj.paths[method.path]) obj.paths[method.path] = {};
            var path = obj.paths[method.path];

            var httpMethod = method.httpMethod.toLowerCase();
            if (!path[httpMethod]) path[httpMethod] = {};

            var op = path[httpMethod];
            op.operationId = m;
            op.description = method.description;
            op.parameters = [];
            for (var p in method.parameters) {
                var param = method.parameters[p];
                param.name = p;
                if (param.title) rename(param,'title','name');
                if ((param.type == 'textarea') || (param.type == 'enumerated')) param.type = 'string';
                if (param.type == 'long') param.type = 'number';
                if (param.type == 'string[]') {
                    param.type = 'array';
                    param.items = {};
                    param.items.type = 'string';
                }
                rename(param,'location','in');
                if (!param["in"]) {
                    if (method.path.indexOf('{'+param.name+'}')>=0) {
                        param["in"] = 'path';
                    }
                    else {
                        param["in"] = 'query';
                    }
                }
                if ((param["in"] == 'body') && (param.type != 'object')) {
                    param["in"] = 'formData'; // revalidate
                }
                if (param["in"] == 'pathReplace') {
                    param["in"] = 'path';
                }
                if (param["in"] == 'path') {
                    param.required = true;
                }
                if (typeof param.required == 'string') {
                    param.required = (param.required === 'true');
                }
                if (param.properties) {
                    delete param.type;
                    param.schema = {};
                    param.schema.type = 'object';
                    param.schema.properties = param.properties;
                    delete param.properties;
                    delete param["default"];
                    fixSchema(param.schema);
                }
                if (param.items) fixSchema(param.items);
                op.parameters.push(param);
            }
            op.tags = [];
            op.tags.push(r);

            op.responses = {};
            op.responses["200"] = {};
            op.responses["200"].description = 'Success';

        }
    }

    delete obj.resources;
    return obj;
}

module.exports = {
    convertSwagger : convertSwagger,
    convertLiveDocs : convertLiveDocs,
    exportIodocs : exportIodocs,
    iodocsUpgrade : iodocsUpgrade
};