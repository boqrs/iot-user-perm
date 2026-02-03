-- 1. 权限用户表（超管SQL初始化）
CREATE TABLE IF NOT EXISTS permission_admin (
    user_id VARCHAR(64) NOT NULL COMMENT '用户ID',
    username VARCHAR(32) NOT NULL COMMENT '用户名',
    password VARCHAR(128) NOT NULL COMMENT 'bcrypt加密密码',
    role_code VARCHAR(32) NOT NULL COMMENT '角色编码：SUPER_ADMIN/ADMIN',
    status VARCHAR(16) NOT NULL DEFAULT 'ENABLED' COMMENT '状态：ENABLED/DISABLED/DELETED',
    is_first_login TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否首次登录',
    remark VARCHAR(255) DEFAULT '' COMMENT '备注',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    UNIQUE KEY uk_username (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='权限用户表';

-- 初始化超管（密码替换为实际bcrypt加密串，示例密码：Admin@123456）
INSERT INTO permission_admin (user_id, username, password, role_code, status, is_first_login, remark)
SELECT 'super_10001', 'super_admin', '$2a$10$e8V97X9k7Lz8G7y6F5d4s3a2b1c0d9e8f7g6h5j4k3l2m1n0b9v8c7x6s5d4f3g2h1j0', 'SUPER_ADMIN', 'ENABLED', 1, '系统初始超管'
    WHERE NOT EXISTS (SELECT 1 FROM permission_admin WHERE role_code = 'SUPER_ADMIN');

-- 2. 角色表
CREATE TABLE IF NOT EXISTS permission_role (
    role_code VARCHAR(32) NOT NULL COMMENT '角色编码',
    role_name VARCHAR(32) NOT NULL COMMENT '角色名称',
    remark VARCHAR(255) DEFAULT '' COMMENT '备注',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (role_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色表';

INSERT INTO permission_role (role_code, role_name, remark) VALUES
('SUPER_ADMIN', '超级管理员', '全权限'),
('ADMIN', '管理员', '仅IOT权限配置');

-- 3. API权限表
CREATE TABLE IF NOT EXISTS permission_api (
    perm_id VARCHAR(64) NOT NULL COMMENT '权限ID',
    perm_name VARCHAR(64) NOT NULL COMMENT '权限名称',
    api_type VARCHAR(16) NOT NULL COMMENT 'API类型：PERMISSION/IOT',
    api_path VARCHAR(128) NOT NULL COMMENT 'API路径',
    api_method VARCHAR(16) NOT NULL COMMENT '请求方法',
    remark VARCHAR(255) DEFAULT '' COMMENT '备注',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (perm_id),
    UNIQUE KEY uk_api (api_type, api_path, api_method)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='API权限表';

-- 4. 角色-API权限绑定表
CREATE TABLE IF NOT EXISTS permission_role_api (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
    role_code VARCHAR(32) NOT NULL COMMENT '角色编码',
    perm_id VARCHAR(64) NOT NULL COMMENT '权限ID',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_role_perm (role_code, perm_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色-API权限绑定表';

-- 5. IOT身份表
CREATE TABLE IF NOT EXISTS permission_iot_identity (
    identity_code VARCHAR(32) NOT NULL COMMENT '身份编码：OWNER/COMMAND/VIEWER',
    identity_name VARCHAR(32) NOT NULL COMMENT '身份名称',
    remark VARCHAR(255) DEFAULT '' COMMENT '备注',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (identity_code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='IOT身份表';

INSERT INTO permission_iot_identity (identity_code, identity_name, remark) VALUES
('OWNER', '拥有者', '设备全权限'),
('COMMAND', '控制者', '查看+控制'),
('VIEWER', '访客', '仅查看');

-- 6. IOT身份-API权限绑定表
CREATE TABLE IF NOT EXISTS permission_iot_identity_api (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
    identity_code VARCHAR(32) NOT NULL COMMENT 'IOT身份编码',
    perm_id VARCHAR(64) NOT NULL COMMENT '权限ID（仅IOT类型）',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_identity_perm (identity_code, perm_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='IOT身份-API权限绑定表';

-- 7. 操作日志表
CREATE TABLE IF NOT EXISTS permission_operation_log (
    log_id VARCHAR(64) NOT NULL COMMENT '日志ID',
    operator_id VARCHAR(64) NOT NULL COMMENT '操作人ID',
    operator_name VARCHAR(32) NOT NULL COMMENT '操作人名称',
    oper_type VARCHAR(32) NOT NULL COMMENT '操作类型',
    oper_content VARCHAR(512) NOT NULL COMMENT '操作内容',
    oper_ip VARCHAR(64) NOT NULL COMMENT '操作IP',
    oper_result VARCHAR(16) NOT NULL COMMENT '成功/失败',
    error_msg VARCHAR(512) DEFAULT '' COMMENT '错误信息',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (log_id),
    INDEX idx_operator (operator_id),
    INDEX idx_create_time (create_time)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='操作日志表';

CREATE TABLE IF NOT EXISTS permission_api (
    perm_id VARCHAR(64) NOT NULL COMMENT '权限ID',
    perm_name VARCHAR(64) NOT NULL COMMENT '权限名称',
    api_type VARCHAR(16) NOT NULL COMMENT 'API类型：PERMISSION（自身）/IOT（IOT微服务）',
    api_path VARCHAR(128) NOT NULL COMMENT 'API路径',
    api_method VARCHAR(16) NOT NULL COMMENT 'API方法：GET/POST/PUT/DELETE',
    remark VARCHAR(255) DEFAULT '' COMMENT '备注',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (perm_id),
    UNIQUE KEY uk_api (api_type, api_path, api_method)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='API权限表';
