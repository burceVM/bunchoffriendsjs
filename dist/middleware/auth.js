"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.allowRoles = void 0;
function allowRoles(...allowedRoles) {
    return function (req, res, next) {
        if (!req.session.user || !allowedRoles.includes(req.session.user.role)) {
            res.status(403).send('Forbidden');
            return;
        }
        next();
    };
}
exports.allowRoles = allowRoles;
//# sourceMappingURL=auth.js.map