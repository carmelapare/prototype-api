require('dotenv').config()

const express = require("express")
const { expressjwt : jwt } = require("express-jwt")
const jwtAuthz = require("express-jwt-authz")
const jwks = require("jwks-rsa");
const cors = require("cors");

const PORT = process.env.PORT || 8080;
const app = express()
app.use(cors())


const jwtCheck = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `${process.env.AUTH0_API}/.well-known/jwks.json`
  }),
  audience:`${process.env.AUTH0_AUDIENCE}`,
  issuer: `${process.env.AUTH0_API}/`,
  algorithms: ['RS256']
});

// Use this for RBAC
// const checkPermissions = jwtAuthz(["read:clients"], {
//     customScopeKey: "permissions"
// })

// Get machine to machine JWT
const getManagementApiJwt = () => {
    let request = require("request")
    return new Promise(function(resolve, reject){
        let options = {
            method: 'POST',
            url: 'https://dev-3bg27e8rs5rruht3.us.auth0.com/oauth/token',
            headers: { 'content-type': 'application/json' },
            body: `{"client_id":"${process.env.CLIENT_ID}","client_secret":"${process.env.CLIENT_SECRET}","audience":"${process.env.AUTH0_API}/api/v2/","grant_type":"client_credentials"}` };
          
        request(options, function (error, response, body) {
            if (error) {
                reject(error)
            } else {
                resolve(JSON.parse(body))
            }
        })
    })
  }
  
function getActions () {
    let request = require("request");
    return new Promise(function(resolve, reject){
        getManagementApiJwt()
        .then(data =>  {
            const token = data.access_token
            let options = { 
                method: 'GET',
                url: `${process.env.AUTH0_API}/api/v2/actions/actions`,
                headers: { 
                    "authorization": "Bearer " + token,
                    "content-type": "application/json"
                }
            }
            request(options, function (error, response, body) {
                if (error) {
                    reject(error)
                } else {
                    resolve(JSON.parse(body))
                }
            })
        })
    })
}

function getClients () {
    let request = require("request");
    return new Promise(function(resolve, reject){
        getManagementApiJwt()
        .then(data =>  {
            const token = data.access_token
            let options = { 
                method: 'GET',
                url: `${process.env.AUTH0_API}/api/v2/clients`,
                headers: { 
                    "authorization": "Bearer " + token,
                    "content-type": "application/json"
                }
            }
            request(options, function (error, response, body) {
                if (error) {
                    reject(error)
                } else {
                    resolve(JSON.parse(body))
                }
            })
        })
    })
}

function parseActions (actions) {
    let actionData = []

    actions.forEach((element) => {
        // Check if app name is specified in action code
        let regex = /(event.client.name(\s*)===(\s*)\".+\")/g
        let matches = String(element.code).match(regex)
        let appNames = []

        if (matches) {
            matches.forEach((str)=>  {
                const appName = str.match(/"(?<app_name>.+)"/).groups?.app_name;
                appNames.push(appName)
            }) 
        }
        actionData.push({
            id: element.id, 
            name: element.name,
            apps: appNames, 
            triggers: element.supported_triggers 
        })
    })
    return actionData
}

async function getApplicationList () {
    let clients = await getClients()
    let actions = await getActions()

    let clientData = []
    clients.forEach((element) => {
        clientData.push({
            id: element.client_id, 
            name: element.name,
            type: element.app_type,
            metadata: element.client_metadata
        })
    })

    let actionData = []
    if (actions && actions.actions) {
        actionData = parseActions(actions.actions)

        actionData.forEach((element) => {
            // If action is not applied to a specific app, 
            // it's assigned to tenant level
            if (element['apps'].length == 0 ) { 
                element['apps'].push(...clientData.map(client => client.name))
            }
        })    
    }

    let applicationData = []
    for (const client of clientData) {
        let actions = []
        if (actionData) {
            for (const action of actionData) {
                if (action['apps'].includes(client.name)) {
                    actions.push(action)
                }
            }
        }
        if (client.name !== 'All Applications') {
            applicationData.push ({
                app_id : client.id,
                app_name : client.name,
                app_type : client.type,
                actions : actions,
                app_metadata: client.metadata
            })
        }
    }
   return applicationData;
}

app.get('/clients', jwtCheck, async function (req, res) {
    let applicationData = await getApplicationList();
    res.json(applicationData);
})

app.get('/', function (req, res) {
    res.json({ message : 'OK'});
})


app.listen(PORT, () => {
    console.log("Running on port " + PORT);
});


