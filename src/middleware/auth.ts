import { Request, Response, NextFunction } from 'express';

export function allowRoles(...allowedRoles: string[]) {
    return function (req: Request, res: Response, next: NextFunction) {
        if (!req.session.user || !allowedRoles.includes(req.session.user.role)) {
            res.status(403).send('Forbidden');
            return;
        }
        next();
    };
}
