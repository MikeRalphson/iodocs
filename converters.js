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

module.exports = {
    convertSwagger : convertSwagger
};