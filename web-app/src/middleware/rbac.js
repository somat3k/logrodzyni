'use strict';

// Role hierarchy: admin > operator > viewer.
const ROLE_LEVEL = { viewer: 1, operator: 2, admin: 3 };

// Factory: returns middleware that requires `requiredRole` or higher.
function requireRole(requiredRole) {
  return (req, res, next) => {
    const userLevel     = ROLE_LEVEL[req.user?.role] || 0;
    const requiredLevel = ROLE_LEVEL[requiredRole]   || 99;

    if (userLevel < requiredLevel) {
      return res.status(403).json({
        error: `Requires role '${requiredRole}' or higher`,
      });
    }
    next();
  };
}

module.exports = { requireRole };
