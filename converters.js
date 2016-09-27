function rename(obj,key,newKey){
    obj[newKey] = obj[key];
    delete obj[key];
}

function convertSwagger(apiInfo){
    apiInfo.resources = {};
    for (var p in apiInfo.paths) {
        for (var m in apiInfo.paths[p]) {
            var sMethod = apiInfo.paths[p][m];
            var ioMethod = {};
            ioMethod.httpMethod = m.toUpperCase();
            var sMethodUniqueName = sMethod.operationId ? sMethod.operationId : m+'_'+p;
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
    delete res.locals.apiInfo.paths; // to keep size down
    rename(apiInfo,'definitions','schemas');
    return apiInfo;
}

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
    //console.log(JSON.stringify(apiInfo,null,2));
    return apiInfo;
}

module.exports = {
    convertSwagger : convertSwagger,
    convertLiveDocs : convertLiveDocs
};