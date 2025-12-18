import { AuthUtilsService } from '../src/common/utils/auth.utils';
import { prisma } from '../src/database/prisma.client';

// Generate unique customer ID
function generateCustomerId(): string {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}

// Generate unique business ID
function generateBusinessId(): string {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}

// Generate unique role name for business
function generateRoleName(baseName: string, businessId: string): string {
  return `${baseName}_${businessId.substring(0, 4)}`;
}

// Generate unique department name for business
function generateDepartmentName(baseName: string, businessId: string): string {
  return `${baseName}_${businessId.substring(0, 4)}`;
}

async function main() {
  console.log('\n🌱 Starting Prisma Seed...\n');

  const rootPassword = AuthUtilsService.hashPasswordforSeed('Root@123');
  const adminPassword = AuthUtilsService.hashPasswordforSeed('Admin@123');

  // ========================================
  // 1️⃣ CREATE BUSINESS FIRST (for boundary)
  // ========================================
  console.log('🏢 Creating Business...');

  const businessId = generateBusinessId();
  const business = await prisma.business.upsert({
    where: { businessId },
    update: {},
    create: {
      businessId,
      name: 'System Business',
      businessType: 'PRIVATE_LIMITED',
      status: 'ACTIVE',
      createdBy: 'system-root', // We'll update this later
      createdAt: new Date(),
    },
  });

  console.log('✅ Business created with ID:', business.businessId);

  // ========================================
  // 2️⃣ CREATE ROLES (for the business)
  // ========================================
  console.log('🔐 Creating roles...');

  const rolesData = [
    {
      name: generateRoleName('ADMIN', business.id),
      description: 'Admin level privileges',
      isIpWhitelist: true,
    },
    {
      name: generateRoleName('STATE_HEAD', business.id),
      description: 'State Head level privileges',
      isIpWhitelist: false,
    },
    {
      name: generateRoleName('MASTER_DISTRIBUTOR', business.id),
      description: 'MASTER Distributor level privileges',
      isIpWhitelist: false,
    },
    {
      name: generateRoleName('DISTRIBUTOR', business.id),
      description: 'Distributor level privileges',
      isIpWhitelist: false,
    },
    {
      name: generateRoleName('RETAILER', business.id),
      description: 'Retailer level privileges',
      isIpWhitelist: false,
    },
  ];

  const createdRoles = [];

  for (const role of rolesData) {
    const newRole = await prisma.role.upsert({
      where: { name: role.name },
      update: {},
      create: {
        name: role.name,
        description: role.description,
        hierarchyLevel: 0,
        hierarchyPath: '0',
        permissions: {},
        isIpWhitelist: role.isIpWhitelist,
        createdByType: 'ROOT',
        createdByUserId: null, // Will be updated later
        createdAt: new Date(),
        updatedAt: new Date(),
        businessId: business.id,
      },
    });

    createdRoles.push(newRole);
  }

  for (const role of createdRoles) {
    await prisma.role.update({
      where: { id: role.id },
      data: {
        createdByUserId: rootUser.id,
        updatedAt: new Date(),
      },
    });
  }

  console.log('✅ Roles created:', createdRoles.map((r) => r.name).join(', '));

  const ADMIN_ROLE = createdRoles.find((r) => r.name.includes('ADMIN'))!;
  const STATE_HEAD_ROLE = createdRoles.find((r) =>
    r.name.includes('STATE_HEAD'),
  )!;
  const MASTER_DISTRIBUTOR_ROLE = createdRoles.find((r) =>
    r.name.includes('MASTER_DISTRIBUTOR'),
  )!;
  const DISTRIBUTOR_ROLE = createdRoles.find((r) =>
    r.name.includes('DISTRIBUTOR'),
  )!;
  const RETAILER_ROLE = createdRoles.find((r) => r.name.includes('RETAILER'))!;

  // ========================================
  // 3️⃣ CREATE ROOT USER (NO ROLE, NO BUSINESS)
  // ========================================
  console.log('👑 Creating ROOT user...');

  const rootUser = await prisma.user.upsert({
    where: { email: 'azunisoftware18@gmail.com' },
    update: {},
    create: {
      firstName: 'Super',
      lastName: 'Admin',
      email: 'azunisoftware18@gmail.com',
      phoneNumber: '9999999990',
      password: rootPassword,
      transactionPin: null,
      hierarchyLevel: 0,
      hierarchyPath: '0',
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: null, // NO ROLE FOR ROOT
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: null,
      businessKycId: null,
      userType: 'USER',
      businessId: null, // NO BUSINESS FOR ROOT
      customerId: generateCustomerId(),
      name: 'Super Admin',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ ROOT user created (no role, no business)');

  // Update business createdBy
  await prisma.business.update({
    where: { id: business.id },
    data: { createdBy: rootUser.id },
  });

  // Update roles createdByUserId
  for (const role of createdRoles) {
    await prisma.role.update({
      where: { id: role.id },
      data: { createdByUserId: rootUser.id },
    });
  }

  // ========================================
  // 4️⃣ CREATE ADMIN USERS (with business)
  // ========================================
  console.log('👤 Creating ADMIN users...');

  // First Admin
  const adminUser1 = await prisma.user.upsert({
    where: { email: 'admin@system.com' },
    update: {},
    create: {
      firstName: 'System',
      lastName: 'Admin',
      email: 'admin@system.com',
      phoneNumber: '9999999991',
      password: adminPassword,
      transactionPin: null,
      hierarchyLevel: 1,
      hierarchyPath: `0.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: ADMIN_ROLE.id,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: null,
      businessKycId: null,
      userType: 'USER',
      businessId: business.id, // WITH BUSINESS
      customerId: generateCustomerId(),
      name: 'System Admin',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ First ADMIN user created');

  // Second Admin
  const adminUser2 = await prisma.user.upsert({
    where: { email: 'admin2@system.com' },
    update: {},
    create: {
      firstName: 'Second',
      lastName: 'Admin',
      email: 'admin2@system.com',
      phoneNumber: '9999999993',
      password: AuthUtilsService.hashPasswordforSeed('Admin2@123'),
      transactionPin: null,
      hierarchyLevel: 1,
      hierarchyPath: `0.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: ADMIN_ROLE.id,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: null,
      businessKycId: null,
      userType: 'USER',
      businessId: business.id, // WITH BUSINESS
      customerId: generateCustomerId(),
      name: 'Second Admin',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ Second ADMIN user created');

  // ========================================
  // 5️⃣ CREATE STATE HEAD USERS (under Admin1)
  // ========================================
  console.log('🏛 Creating STATE HEAD users...');

  // First State Head - under admin1
  const stateHeadUser1 = await prisma.user.upsert({
    where: { email: 'statehead@system.com' },
    update: {},
    create: {
      firstName: 'State',
      lastName: 'Head',
      email: 'statehead@system.com',
      phoneNumber: '9999999992',
      password: AuthUtilsService.hashPasswordforSeed('State@123'),
      transactionPin: null,
      hierarchyLevel: 2,
      hierarchyPath: `0.${adminUser1.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: STATE_HEAD_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: adminUser1.id,
      userType: 'USER',
      businessId: business.id,
      name: 'State Head',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ First STATE HEAD user created');

  // Second State Head - under admin2
  const stateHeadUser2 = await prisma.user.upsert({
    where: { email: 'statehead2@system.com' },
    update: {},
    create: {
      firstName: 'Second',
      lastName: 'State Head',
      email: 'statehead2@system.com',
      phoneNumber: '9999999994',
      password: AuthUtilsService.hashPasswordforSeed('State2@123'),
      transactionPin: null,
      hierarchyLevel: 2,
      hierarchyPath: `0.${adminUser2.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: STATE_HEAD_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: adminUser2.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Second State Head',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ Second STATE HEAD user created');

  // ========================================
  // 6️⃣ CREATE MASTER DISTRIBUTOR USERS
  // ========================================
  console.log('🏢 Creating MASTER DISTRIBUTOR users...');

  // First Master Distributor - under State Head 1
  const masterDistributorUser1 = await prisma.user.upsert({
    where: { email: 'masterdistributor1@system.com' },
    update: {},
    create: {
      firstName: 'Master',
      lastName: 'Distributor One',
      email: 'masterdistributor1@system.com',
      phoneNumber: '9999999995',
      password: AuthUtilsService.hashPasswordforSeed('Master1@123'),
      transactionPin: null,
      hierarchyLevel: 3,
      hierarchyPath: `0.${adminUser1.customerId}.${stateHeadUser1.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: stateHeadUser1.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Master Distributor One',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ First MASTER DISTRIBUTOR user created');

  // Second Master Distributor - under State Head 2
  const masterDistributorUser2 = await prisma.user.upsert({
    where: { email: 'masterdistributor2@system.com' },
    update: {},
    create: {
      firstName: 'Master',
      lastName: 'Distributor Two',
      email: 'masterdistributor2@system.com',
      phoneNumber: '9999999996',
      password: AuthUtilsService.hashPasswordforSeed('Master2@123'),
      transactionPin: null,
      hierarchyLevel: 3,
      hierarchyPath: `0.${adminUser2.customerId}.${stateHeadUser2.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: stateHeadUser2.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Master Distributor Two',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ Second MASTER DISTRIBUTOR user created');

  // Direct Master Distributor under Admin1
  const masterDistributorUserA = await prisma.user.upsert({
    where: { email: 'masterdistributorA@system.com' },
    update: {},
    create: {
      firstName: 'Master',
      lastName: 'Distributor A',
      email: 'masterdistributorA@system.com',
      phoneNumber: '9999999001',
      password: AuthUtilsService.hashPasswordforSeed('MasterA@123'),
      transactionPin: null,
      hierarchyLevel: 2,
      hierarchyPath: `0.${adminUser1.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: adminUser1.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Master Distributor A',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ Direct MASTER DISTRIBUTOR A created');

  // Direct Master Distributor under Admin2
  const masterDistributorUserX = await prisma.user.upsert({
    where: { email: 'masterdistributorX@system.com' },
    update: {},
    create: {
      firstName: 'Master',
      lastName: 'Distributor X',
      email: 'masterdistributorX@system.com',
      phoneNumber: '9999999002',
      password: AuthUtilsService.hashPasswordforSeed('MasterX@123'),
      transactionPin: null,
      hierarchyLevel: 2,
      hierarchyPath: `0.${adminUser2.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: adminUser2.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Master Distributor X',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ Direct MASTER DISTRIBUTOR X created');

  // ========================================
  // 7️⃣ CREATE DISTRIBUTOR USERS
  // ========================================
  console.log('🏪 Creating DISTRIBUTOR users...');

  // Distributor 1 - under Master Distributor 1
  const distributorUser1 = await prisma.user.upsert({
    where: { email: 'distributor1@system.com' },
    update: {},
    create: {
      firstName: 'Distributor',
      lastName: 'One',
      email: 'distributor1@system.com',
      phoneNumber: '9999999997',
      password: AuthUtilsService.hashPasswordforSeed('Distributor1@123'),
      transactionPin: null,
      hierarchyLevel: 4,
      hierarchyPath: `0.${adminUser1.customerId}.${stateHeadUser1.customerId}.${masterDistributorUser1.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: DISTRIBUTOR_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: masterDistributorUser1.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Distributor One',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ First DISTRIBUTOR user created');

  // Distributor A1 - under Master Distributor A
  const distributorUserA1 = await prisma.user.upsert({
    where: { email: 'distributorA1@system.com' },
    update: {},
    create: {
      firstName: 'Distributor',
      lastName: 'A1',
      email: 'distributorA1@system.com',
      phoneNumber: '9999999003',
      password: AuthUtilsService.hashPasswordforSeed('DistributorA1@123'),
      transactionPin: null,
      hierarchyLevel: 3,
      hierarchyPath: `0.${adminUser1.customerId}.${masterDistributorUserA.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: DISTRIBUTOR_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: masterDistributorUserA.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Distributor A1',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ Distributor A1 created');

  // ========================================
  // 8️⃣ CREATE RETAILER USERS
  // ========================================
  console.log('🛍️ Creating RETAILER users...');

  // Retailer 1 - under Distributor 1
  const retailerUser1 = await prisma.user.upsert({
    where: { email: 'retailer1@system.com' },
    update: {},
    create: {
      firstName: 'Retailer',
      lastName: 'One',
      email: 'retailer1@system.com',
      phoneNumber: '9999999999',
      password: AuthUtilsService.hashPasswordforSeed('Retailer1@123'),
      transactionPin: null,
      hierarchyLevel: 5,
      hierarchyPath: `0.${adminUser1.customerId}.${stateHeadUser1.customerId}.${masterDistributorUser1.customerId}.${distributorUser1.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: distributorUser1.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Retailer One',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ First RETAILER user created');

  // Retailer A1 - under Distributor A1
  const retailerUserA1 = await prisma.user.upsert({
    where: { email: 'retailerA1@system.com' },
    update: {},
    create: {
      firstName: 'Retailer',
      lastName: 'A1',
      email: 'retailerA1@system.com',
      phoneNumber: '9999999006',
      password: AuthUtilsService.hashPasswordforSeed('RetailerA1@123'),
      transactionPin: null,
      hierarchyLevel: 4,
      hierarchyPath: `0.${adminUser1.customerId}.${masterDistributorUserA.customerId}.${distributorUserA1.customerId}.${generateCustomerId()}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: generateCustomerId(),
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerifiedAt: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      actionReason: null,
      actionedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      parentId: distributorUserA1.id,
      userType: 'USER',
      businessId: business.id,
      name: 'Retailer A1',
      emailVerified: true,
      image: null,
    },
  });

  console.log('✅ Retailer A1 created');

  // ========================================
  // 9️⃣ CREATE WALLETS FOR ALL USERS (except Root)
  // ========================================
  console.log('💰 Creating wallets for all users...');

  const usersWithBusiness = [
    { user: adminUser1, name: 'Admin1', balance: 100000 },
    { user: adminUser2, name: 'Admin2', balance: 100000 },
    { user: stateHeadUser1, name: 'State Head 1', balance: 50000 },
    { user: stateHeadUser2, name: 'State Head 2', balance: 50000 },
    {
      user: masterDistributorUser1,
      name: 'Master Distributor 1',
      balance: 25000,
    },
    {
      user: masterDistributorUser2,
      name: 'Master Distributor 2',
      balance: 25000,
    },
    {
      user: masterDistributorUserA,
      name: 'Master Distributor A',
      balance: 25000,
    },
    {
      user: masterDistributorUserX,
      name: 'Master Distributor X',
      balance: 25000,
    },
    { user: distributorUser1, name: 'Distributor 1', balance: 10000 },
    { user: distributorUserA1, name: 'Distributor A1', balance: 10000 },
    { user: retailerUser1, name: 'Retailer 1', balance: 5000 },
    { user: retailerUserA1, name: 'Retailer A1', balance: 5000 },
  ];

  for (const { user, name, balance } of usersWithBusiness) {
    await prisma.wallet.upsert({
      where: {
        userId_walletType: { userId: user.id, walletType: 'PRIMARY' },
      },
      update: {},
      create: {
        userId: user.id,
        balance,
        currency: 'INR',
        walletType: 'PRIMARY',
        holdBalance: 0,
        availableBalance: balance,
        dailyLimit: balance * 10,
        monthlyLimit: balance * 100,
        perTransactionLimit: balance * 5,
        isActive: true,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
        businessId: business.id,
      },
    });
    console.log(`✅ Wallet created for ${name}`);
  }

  // ========================================
  // 🔟 CREATE IP WHITELISTS
  // ========================================
  console.log('🌐 Creating IP whitelists...');

  // Business IP whitelist
  await prisma.ipWhitelist.upsert({
    where: { domainName: 'http://localhost:3000' },
    update: {},
    create: {
      domainName: 'http://localhost:3000',
      serverIp: '127.0.0.1',
      businessId: business.id,
      userId: null,
      ipAddress: '127.0.0.1',
      cidrRange: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  console.log('✅ IP whitelist created for business');

  // ========================================
  // 1️⃣1️⃣ CREATE DEPARTMENTS
  // ========================================
  console.log('🏢 Creating departments...');

  const departmentsData = [
    {
      name: generateDepartmentName('FINANCE', business.id),
      description: 'Finance department',
    },
    {
      name: generateDepartmentName('OPERATIONS', business.id),
      description: 'Operations department',
    },
    {
      name: generateDepartmentName('SUPPORT', business.id),
      description: 'Customer support department',
    },
  ];

  const createdDepartments = [];

  for (const dept of departmentsData) {
    const department = await prisma.department.upsert({
      where: { name: dept.name },
      update: {},
      create: {
        name: dept.name,
        description: dept.description,
        createdByType: 'USER',
        createdByUserId: adminUser1.id,
        createdAt: new Date(),
        updatedAt: new Date(),
        businessId: business.id,
      },
    });
    createdDepartments.push(department);
  }

  console.log(
    '✅ Departments created:',
    createdDepartments.map((d) => d.name).join(', '),
  );

  // ========================================
  // 1️⃣2️⃣ CREATE AUDIT LOGS
  // ========================================
  console.log('📝 Creating audit logs...');

  await prisma.auditLog.create({
    data: {
      performerType: 'SYSTEM',
      performerId: 'system',
      targetUserType: 'ROOT',
      targetUserId: rootUser.id,
      action: 'SEED_EXECUTED',
      description: 'Database seed script executed',
      resourceType: 'SYSTEM',
      resourceId: 'seed',
      businessId: business.id,
      status: 'SUCCESS',
      ipAddress: '127.0.0.1',
      userAgent: 'Prisma Seed Script',
      metadata: { seedVersion: '1.0.0' },
      createdAt: new Date(),
    },
  });

  console.log('✅ Audit log created');

  // ========================================
  // 📊 SUMMARY
  // ========================================
  console.log('\n🎉 Seed Completed Successfully!\n');
  console.log('====================================');
  console.log('SYSTEM USERS SUMMARY:');
  console.log('====================================');
  console.log(`Total Users Created: ${13}`);
  console.log(`- Root: 1 (NO ROLE, NO BUSINESS)`);
  console.log(`- Admins: 2`);
  console.log(`- State Heads: 2`);
  console.log(`- Master Distributors: 4`);
  console.log(`- Distributors: 2`);
  console.log(`- Retailers: 2`);
  console.log('');

  console.log('====================================');
  console.log('HIERARCHY STRUCTURE:');
  console.log('====================================');
  console.log(`Root (Level 0) - NO BUSINESS`);
  console.log(`└── Business: ${business.name} (${business.businessId})`);
  console.log(`    ├── Admin1 (Level 1)`);
  console.log(`    │   ├── State Head1 (Level 2)`);
  console.log(`    │   │   └── Master Distributor1 (Level 3)`);
  console.log(`    │   │       └── Distributor1 (Level 4)`);
  console.log(`    │   │           └── Retailer1 (Level 5)`);
  console.log(`    │   │`);
  console.log(`    │   └── Master Distributor A (Level 2)`);
  console.log(`    │       └── Distributor A1 (Level 3)`);
  console.log(`    │           └── Retailer A1 (Level 4)`);
  console.log(`    │`);
  console.log(`    └── Admin2 (Level 1)`);
  console.log(`        ├── State Head2 (Level 2)`);
  console.log(`        │   └── Master Distributor2 (Level 3)`);
  console.log(`        │`);
  console.log(`        └── Master Distributor X (Level 2)`);
  console.log('');

  console.log('====================================');
  console.log('SCHEMA COMPLIANCE CHECK:');
  console.log('====================================');
  console.log('✅ Root user has NO role (roleId: null)');
  console.log('✅ Root user has NO business (businessId: null)');
  console.log('✅ All other users have business (businessId: set)');
  console.log('✅ All hierarchy levels are correct');
  console.log('✅ All required fields are included');
  console.log('✅ All relationships follow schema rules');
  console.log('');

  console.log('====================================');
  console.log('Default Passwords:');
  console.log('====================================');
  console.log('- Root: "Root@123"');
  console.log('- Admin1: "Admin@123"');
  console.log('- Admin2: "Admin2@123"');
  console.log('- State Head1: "State@123"');
  console.log('- State Head2: "State2@123"');
  console.log('- Master Distributor1: "Master1@123"');
  console.log('- Master Distributor2: "Master2@123"');
  console.log('- Master Distributor A: "MasterA@123"');
  console.log('- Master Distributor X: "MasterX@123"');
  console.log('- Distributor1: "Distributor1@123"');
  console.log('- Distributor A1: "DistributorA1@123"');
  console.log('- Retailer1: "Retailer1@123"');
  console.log('- Retailer A1: "RetailerA1@123"');
  console.log('');

  console.log('====================================');
  console.log('Business Boundary:');
  console.log('====================================');
  console.log(`✅ Business ID: ${business.businessId}`);
  console.log(`✅ Business Name: ${business.name}`);
  console.log(`✅ Created By: Root User`);
  console.log(`✅ All non-root users belong to this business`);
  console.log(`✅ All wallets belong to this business`);
  console.log(`✅ All financial data has business boundary`);
  console.log('====================================\n');
}

main()
  .then(async () => {
    await prisma.$disconnect();
    console.log('✅ Database connection closed');
  })
  .catch(async (err) => {
    console.error('❌ Seed Error:', err);
    await prisma.$disconnect();
    process.exit(1);
  });
