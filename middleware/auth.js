const jwt = require('jsonwebtoken')

function validateJWT(req, res, next) {
    const authHeader = req.headers['authorization']

    if (authHeader) {
        // attempt vaildation
        try {
            const token = authHeader.split(' ')[1]
            const validToken = jwt.verify(token, process.env.JWT_SECRET)
            req.user = validToken
            next()
            return;
        } catch (error) {
            res.status(401).json({ 'message': 'unathorized' })
        }
    } else {
        res.status(401).json({ 'message': 'unathorized' })
    return;
    }

}

module.exports = {
    validateJWT
}