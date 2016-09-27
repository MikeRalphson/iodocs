var url = require('url');
var clone = require('clone');

function rename(obj,key,newKey){
    obj[newKey] = obj[key];
    delete obj[key];
}

/**
* function to reformat swagger paths object into an iodocs-style resources object
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
    rename(apiInfo,'prefix','basePath');
    apiInfo.basePath = 'http://'+apiInfo.server+apiInfo.basePath;
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
                params[lParam.name] = lParam;
                delete lParam.name;
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
* function to convert modern iodocs format to swagger 2.0
*/
function exportIodocs(src){
    var obj = clone(src);
    obj.swagger = '2.0';
    obj.info = {};
    obj.info.version = obj.version;
    obj.info.title = obj.name;
    obj.paths = {};

    var u = url.parse(obj.basePath);
    obj.schemes = [];
    obj.schemes.push(u.protocol.replace(':',''));
    obj.host = u.host;
    obj.basePath = u.path;

    delete obj.version;
    delete obj.publicPath;
    delete obj.protocol;
    delete obj.name;
    delete obj.auth; // TODO

    for (var r in obj.resources) {
        var resource = obj.resources[r];
        // do tags
        for (var m in resource.methods) {
            var method = resource.methods[m];

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
                rename(param,'location','in');
                if (!param["in"]) {
                    param["in"] = 'path';
                }
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
    exportIodocs : exportIodocs
};