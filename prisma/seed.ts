import { PrismaMariaDb } from '@prisma/adapter-mariadb';
import { PrismaClient } from '../generated/prisma/client';
import type { Role } from '../generated/prisma/client';
import { AuthUtilsService } from '../src/auth/helper/auth-utils';

// Generate unique customer ID
function generateCustomerId(): string {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}

// DB adapter
const adapter = new PrismaMariaDb({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
  connectionLimit: 10,
});

const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('\n🌱 Starting Prisma Seed...\n');

  const rootPassword = AuthUtilsService.hashPasswordforSeed('Root@123');
  const adminPassword = AuthUtilsService.hashPasswordforSeed('Admin@123');

  // ========================================
  // 1️⃣ CREATE ROOT USER WITH NULL ROLE FIRST
  // ========================================
  console.log('👑 Creating ROOT user (Root table)...');
  const rootUser = await prisma.root.upsert({
    where: { username: 'root' },
    update: {},
    create: {
      username: 'root',
      firstName: 'Super',
      lastName: 'Admin',
      email: 'azunisoftware18@gmail.com',
      phoneNumber: '9999999990',
      password: rootPassword,
      status: 'ACTIVE',
      hierarchyLevel: 0,
      hierarchyPath: '0',
      roleId: null, // Will be updated later
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      lastLoginAt: null,
      lastLoginIp: null,
      lastLoginOrigin: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log('✅ ROOT user created');

  // ========================================
  // 2️⃣ CREATE ROLES (now that root exists)
  // ========================================
  console.log('🔐 Creating roles...');
  const rolesData = [
    {
      name: 'ROOT',
      description: 'Full system access (for Root users)',
    },
    {
      name: 'ADMIN',
      description: 'Admin level privileges',
    },
    {
      name: 'STATE HEAD',
      description: 'State Head level privileges',
    },
    {
      name: 'MASTER DISTRIBUTOR',
      description: 'MASTER Distributor level privileges',
    },
    {
      name: 'DISTRIBUTOR',
      description: 'Distributor level privileges',
    },
    {
      name: 'RETAILER',
      description: 'Retailer level privileges',
    },
  ];

  const createdRoles: Role[] = [];

  for (const role of rolesData) {
    const newRole = await prisma.role.upsert({
      where: { name: role.name },
      update: {},
      create: {
        name: role.name,
        description: role.description,
        createdByType: 'ROOT',
        createdByRootId: rootUser.id,
        createdByUserId: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });

    createdRoles.push(newRole);
  }

  console.log('✅ Roles created:', createdRoles.map((r) => r.name).join(', '));

  const ROOT_ROLE = createdRoles.find((r) => r.name === 'ROOT')!;
  const ADMIN_ROLE = createdRoles.find((r) => r.name === 'ADMIN')!;
  const STATE_HEAD_ROLE = createdRoles.find((r) => r.name === 'STATE HEAD')!;
  const MASTER_DISTRIBUTOR_ROLE = createdRoles.find(
    (r) => r.name === 'MASTER DISTRIBUTOR',
  )!;
  const DISTRIBUTOR_ROLE = createdRoles.find((r) => r.name === 'DISTRIBUTOR')!;
  const RETAILER_ROLE = createdRoles.find((r) => r.name === 'RETAILER')!;

  // ========================================
  // 3️⃣ ASSIGN ROOT ROLE TO ROOT USER
  // ========================================
  console.log('🔗 Assigning ROOT role to root user...');
  await prisma.root.update({
    where: { id: rootUser.id },
    data: { roleId: ROOT_ROLE.id },
  });

  console.log('✅ ROOT role assigned');

  // ========================================
  // 4️⃣ CREATE ADMIN USERS (in User table)
  // ========================================
  console.log('👤 Creating ADMIN users (User table)...');

  // First Admin
  const admin1CustomerId = generateCustomerId();
  const adminUser1 = await prisma.user.upsert({
    where: { username: 'admin' },
    update: {},
    create: {
      username: 'admin',
      firstName: 'System',
      lastName: 'Admin',
      email: 'admin@system.com',
      phoneNumber: '9999999991',
      password: adminPassword,
      transactionPin: null,
      transactionPinSalt: null,
      parentId: null,
      rootParentId: rootUser.id,
      hierarchyLevel: 1,
      hierarchyPath: `0.${admin1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: ADMIN_ROLE.id,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      customerId: admin1CustomerId,
      businessKycId: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ First ADMIN user created with customer ID:',
    admin1CustomerId,
  );

  // Second Admin
  const admin2CustomerId = generateCustomerId();
  const adminUser2 = await prisma.user.upsert({
    where: { username: 'admin2' },
    update: {},
    create: {
      username: 'admin2',
      firstName: 'Second',
      lastName: 'Admin',
      email: 'admin2@system.com',
      phoneNumber: '9999999993',
      password: AuthUtilsService.hashPasswordforSeed('Admin2@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: null,
      rootParentId: rootUser.id,
      hierarchyLevel: 1,
      hierarchyPath: `0.${admin2CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: ADMIN_ROLE.id,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      customerId: admin2CustomerId,
      businessKycId: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Second ADMIN user created with customer ID:',
    admin2CustomerId,
  );

  // ========================================
  // 5️⃣ CREATE STATE HEAD USERS (under Admin1)
  // ========================================
  console.log('🏛 Creating STATE HEAD users...');

  // First State Head - under admin1
  const stateHead1CustomerId = generateCustomerId();
  const stateHeadUser1 = await prisma.user.upsert({
    where: { username: 'statehead' },
    update: {},
    create: {
      username: 'statehead',
      firstName: 'State',
      lastName: 'Head',
      email: 'statehead@system.com',
      phoneNumber: '9999999992',
      password: AuthUtilsService.hashPasswordforSeed('State@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 2,
      hierarchyPath: `0.${admin1CustomerId}.${stateHead1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: STATE_HEAD_ROLE.id,
      customerId: stateHead1CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ First STATE HEAD user created with customer ID:',
    stateHead1CustomerId,
  );

  // Second State Head - under admin2
  const stateHead2CustomerId = generateCustomerId();
  const stateHeadUser2 = await prisma.user.upsert({
    where: { username: 'statehead2' },
    update: {},
    create: {
      username: 'statehead2',
      firstName: 'Second',
      lastName: 'State Head',
      email: 'statehead2@system.com',
      phoneNumber: '9999999994',
      password: AuthUtilsService.hashPasswordforSeed('State2@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser2.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 2,
      hierarchyPath: `0.${admin2CustomerId}.${stateHead2CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: STATE_HEAD_ROLE.id,
      customerId: stateHead2CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Second STATE HEAD user created with customer ID:',
    stateHead2CustomerId,
  );

  // ========================================
  // 6️⃣ CREATE MASTER DISTRIBUTOR USERS
  // ========================================
  console.log('🏢 Creating MASTER DISTRIBUTOR users...');

  // First Master Distributor - under State Head 1
  const masterDistributor1CustomerId = generateCustomerId();
  const masterDistributorUser1 = await prisma.user.upsert({
    where: { username: 'masterdistributor1' },
    update: {},
    create: {
      username: 'masterdistributor1',
      firstName: 'Master',
      lastName: 'Distributor One',
      email: 'masterdistributor1@system.com',
      phoneNumber: '9999999995',
      password: AuthUtilsService.hashPasswordforSeed('Master1@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: stateHeadUser1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 3,
      hierarchyPath: `0.${admin1CustomerId}.${stateHead1CustomerId}.${masterDistributor1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: masterDistributor1CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ First MASTER DISTRIBUTOR user created with customer ID:',
    masterDistributor1CustomerId,
  );

  // Second Master Distributor - under State Head 2
  const masterDistributor2CustomerId = generateCustomerId();
  const masterDistributorUser2 = await prisma.user.upsert({
    where: { username: 'masterdistributor2' },
    update: {},
    create: {
      username: 'masterdistributor2',
      firstName: 'Master',
      lastName: 'Distributor Two',
      email: 'masterdistributor2@system.com',
      phoneNumber: '9999999996',
      password: AuthUtilsService.hashPasswordforSeed('Master2@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: stateHeadUser2.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 3,
      hierarchyPath: `0.${admin2CustomerId}.${stateHead2CustomerId}.${masterDistributor2CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: masterDistributor2CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Second MASTER DISTRIBUTOR user created with customer ID:',
    masterDistributor2CustomerId,
  );

  // ========================================
  // 7️⃣ CREATE DIRECT MASTER DISTRIBUTOR UNDER ADMIN1
  // ========================================
  console.log('🏢 Creating Direct MASTER DISTRIBUTOR under Admin1...');

  // Master Distributor A - directly under Admin1
  const masterDistributorACustomerId = generateCustomerId();
  const masterDistributorUserA = await prisma.user.upsert({
    where: { username: 'masterdistributorA' },
    update: {},
    create: {
      username: 'masterdistributorA',
      firstName: 'Master',
      lastName: 'Distributor A',
      email: 'masterdistributorA@system.com',
      phoneNumber: '9999999001',
      password: AuthUtilsService.hashPasswordforSeed('MasterA@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 3,
      hierarchyPath: `0.${admin1CustomerId}.${masterDistributorACustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: masterDistributorACustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Direct MASTER DISTRIBUTOR A created with customer ID:',
    masterDistributorACustomerId,
  );

  // ========================================
  // 8️⃣ CREATE DIRECT MASTER DISTRIBUTOR UNDER ADMIN2
  // ========================================
  console.log('🏢 Creating Direct MASTER DISTRIBUTOR under Admin2...');

  // Master Distributor X - directly under Admin2
  const masterDistributorXCustomerId = generateCustomerId();
  const masterDistributorUserX = await prisma.user.upsert({
    where: { username: 'masterdistributorX' },
    update: {},
    create: {
      username: 'masterdistributorX',
      firstName: 'Master',
      lastName: 'Distributor X',
      email: 'masterdistributorX@system.com',
      phoneNumber: '9999999002',
      password: AuthUtilsService.hashPasswordforSeed('MasterX@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser2.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 3,
      hierarchyPath: `0.${admin2CustomerId}.${masterDistributorXCustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: MASTER_DISTRIBUTOR_ROLE.id,
      customerId: masterDistributorXCustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Direct MASTER DISTRIBUTOR X created with customer ID:',
    masterDistributorXCustomerId,
  );

  // ========================================
  // 9️⃣ CREATE DISTRIBUTOR USERS
  // ========================================
  console.log('🏪 Creating DISTRIBUTOR users...');

  // Distributor 1 - under Master Distributor 1
  const distributor1CustomerId = generateCustomerId();
  const distributorUser1 = await prisma.user.upsert({
    where: { username: 'distributor1' },
    update: {},
    create: {
      username: 'distributor1',
      firstName: 'Distributor',
      lastName: 'One',
      email: 'distributor1@system.com',
      phoneNumber: '9999999997',
      password: AuthUtilsService.hashPasswordforSeed('Distributor1@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: masterDistributorUser1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 4,
      hierarchyPath: `0.${admin1CustomerId}.${stateHead1CustomerId}.${masterDistributor1CustomerId}.${distributor1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: DISTRIBUTOR_ROLE.id,
      customerId: distributor1CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ First DISTRIBUTOR user created with customer ID:',
    distributor1CustomerId,
  );

  // Distributor 2 - under Master Distributor 2
  const distributor2CustomerId = generateCustomerId();
  const distributorUser2 = await prisma.user.upsert({
    where: { username: 'distributor2' },
    update: {},
    create: {
      username: 'distributor2',
      firstName: 'Distributor',
      lastName: 'Two',
      email: 'distributor2@system.com',
      phoneNumber: '9999999998',
      password: AuthUtilsService.hashPasswordforSeed('Distributor2@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: masterDistributorUser2.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 4,
      hierarchyPath: `0.${admin2CustomerId}.${stateHead2CustomerId}.${masterDistributor2CustomerId}.${distributor2CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: DISTRIBUTOR_ROLE.id,
      customerId: distributor2CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Second DISTRIBUTOR user created with customer ID:',
    distributor2CustomerId,
  );

  // Distributor A1 - under Master Distributor A
  const distributorA1CustomerId = generateCustomerId();
  const distributorUserA1 = await prisma.user.upsert({
    where: { username: 'distributorA1' },
    update: {},
    create: {
      username: 'distributorA1',
      firstName: 'Distributor',
      lastName: 'A1',
      email: 'distributorA1@system.com',
      phoneNumber: '9999999003',
      password: AuthUtilsService.hashPasswordforSeed('DistributorA1@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: masterDistributorUserA.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 4,
      hierarchyPath: `0.${admin1CustomerId}.${masterDistributorACustomerId}.${distributorA1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: DISTRIBUTOR_ROLE.id,
      customerId: distributorA1CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Distributor A1 created with customer ID:',
    distributorA1CustomerId,
  );

  // ========================================
  // 🔟 CREATE DIRECT DISTRIBUTOR UNDER ADMIN1
  // ========================================
  console.log('🏪 Creating Direct DISTRIBUTOR under Admin1...');

  // Distributor B - directly under Admin1
  const distributorBCustomerId = generateCustomerId();
  const distributorUserB = await prisma.user.upsert({
    where: { username: 'distributorB' },
    update: {},
    create: {
      username: 'distributorB',
      firstName: 'Distributor',
      lastName: 'B',
      email: 'distributorB@system.com',
      phoneNumber: '9999999004',
      password: AuthUtilsService.hashPasswordforSeed('DistributorB@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 4,
      hierarchyPath: `0.${admin1CustomerId}.${distributorBCustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: DISTRIBUTOR_ROLE.id,
      customerId: distributorBCustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Direct DISTRIBUTOR B created with customer ID:',
    distributorBCustomerId,
  );

  // ========================================
  // 11️⃣ CREATE DIRECT DISTRIBUTOR UNDER ADMIN2
  // ========================================
  console.log('🏪 Creating Direct DISTRIBUTOR under Admin2...');

  // Distributor Y - directly under Admin2
  const distributorYCustomerId = generateCustomerId();
  const distributorUserY = await prisma.user.upsert({
    where: { username: 'distributorY' },
    update: {},
    create: {
      username: 'distributorY',
      firstName: 'Distributor',
      lastName: 'Y',
      email: 'distributorY@system.com',
      phoneNumber: '9999999005',
      password: AuthUtilsService.hashPasswordforSeed('DistributorY@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser2.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 4,
      hierarchyPath: `0.${admin2CustomerId}.${distributorYCustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: DISTRIBUTOR_ROLE.id,
      customerId: distributorYCustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Direct DISTRIBUTOR Y created with customer ID:',
    distributorYCustomerId,
  );

  // ========================================
  // 12️⃣ CREATE RETAILER USERS
  // ========================================
  console.log('🛍️ Creating RETAILER users...');

  // Retailer 1 - under Distributor 1
  const retailer1CustomerId = generateCustomerId();
  const retailerUser1 = await prisma.user.upsert({
    where: { username: 'retailer1' },
    update: {},
    create: {
      username: 'retailer1',
      firstName: 'Retailer',
      lastName: 'One',
      email: 'retailer1@system.com',
      phoneNumber: '9999999999',
      password: AuthUtilsService.hashPasswordforSeed('Retailer1@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: distributorUser1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 5,
      hierarchyPath: `0.${admin1CustomerId}.${stateHead1CustomerId}.${masterDistributor1CustomerId}.${distributor1CustomerId}.${retailer1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: retailer1CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ First RETAILER user created with customer ID:',
    retailer1CustomerId,
  );

  // Retailer 2 - under Distributor 2
  const retailer2CustomerId = generateCustomerId();
  const retailerUser2 = await prisma.user.upsert({
    where: { username: 'retailer2' },
    update: {},
    create: {
      username: 'retailer2',
      firstName: 'Retailer',
      lastName: 'Two',
      email: 'retailer2@system.com',
      phoneNumber: '9999999990',
      password: AuthUtilsService.hashPasswordforSeed('Retailer2@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: distributorUser2.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 5,
      hierarchyPath: `0.${admin2CustomerId}.${stateHead2CustomerId}.${masterDistributor2CustomerId}.${distributor2CustomerId}.${retailer2CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: retailer2CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Second RETAILER user created with customer ID:',
    retailer2CustomerId,
  );

  // Retailer A1 - under Distributor A1
  const retailerA1CustomerId = generateCustomerId();
  const retailerUserA1 = await prisma.user.upsert({
    where: { username: 'retailerA1' },
    update: {},
    create: {
      username: 'retailerA1',
      firstName: 'Retailer',
      lastName: 'A1',
      email: 'retailerA1@system.com',
      phoneNumber: '9999999006',
      password: AuthUtilsService.hashPasswordforSeed('RetailerA1@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: distributorUserA1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 5,
      hierarchyPath: `0.${admin1CustomerId}.${masterDistributorACustomerId}.${distributorA1CustomerId}.${retailerA1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: retailerA1CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log('✅ Retailer A1 created with customer ID:', retailerA1CustomerId);

  // Retailer B1 - under Distributor B
  const retailerB1CustomerId = generateCustomerId();
  const retailerUserB1 = await prisma.user.upsert({
    where: { username: 'retailerB1' },
    update: {},
    create: {
      username: 'retailerB1',
      firstName: 'Retailer',
      lastName: 'B1',
      email: 'retailerB1@system.com',
      phoneNumber: '9999999007',
      password: AuthUtilsService.hashPasswordforSeed('RetailerB1@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: distributorUserB.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 5,
      hierarchyPath: `0.${admin1CustomerId}.${distributorBCustomerId}.${retailerB1CustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: retailerB1CustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log('✅ Retailer B1 created with customer ID:', retailerB1CustomerId);

  // ========================================
  // 13️⃣ CREATE DIRECT RETAILER UNDER ADMIN1
  // ========================================
  console.log('🛍️ Creating Direct RETAILER under Admin1...');

  // Retailer C - directly under Admin1
  const retailerCCustomerId = generateCustomerId();
  const retailerUserC = await prisma.user.upsert({
    where: { username: 'retailerC' },
    update: {},
    create: {
      username: 'retailerC',
      firstName: 'Retailer',
      lastName: 'C',
      email: 'retailerC@system.com',
      phoneNumber: '9999999008',
      password: AuthUtilsService.hashPasswordforSeed('RetailerC@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser1.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 5,
      hierarchyPath: `0.${admin1CustomerId}.${retailerCCustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: retailerCCustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Direct RETAILER C created with customer ID:',
    retailerCCustomerId,
  );

  // ========================================
  // 14️⃣ CREATE DIRECT RETAILER UNDER ADMIN2
  // ========================================
  console.log('🛍️ Creating Direct RETAILER under Admin2...');

  // Retailer Z - directly under Admin2
  const retailerZCustomerId = generateCustomerId();
  const retailerUserZ = await prisma.user.upsert({
    where: { username: 'retailerZ' },
    update: {},
    create: {
      username: 'retailerZ',
      firstName: 'Retailer',
      lastName: 'Z',
      email: 'retailerZ@system.com',
      phoneNumber: '9999999009',
      password: AuthUtilsService.hashPasswordforSeed('RetailerZ@123'),
      transactionPin: null,
      transactionPinSalt: null,
      parentId: adminUser2.id,
      rootParentId: rootUser.id,
      hierarchyLevel: 5,
      hierarchyPath: `0.${admin2CustomerId}.${retailerZCustomerId}`,
      status: 'ACTIVE',
      isKycVerified: false,
      roleId: RETAILER_ROLE.id,
      customerId: retailerZCustomerId,
      businessKycId: null,
      refreshToken: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      emailVerificationToken: null,
      emailVerifiedAt: null,
      emailVerificationTokenExpires: null,
      lastLoginAt: null,
      deactivationReason: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  console.log(
    '✅ Direct RETAILER Z created with customer ID:',
    retailerZCustomerId,
  );

  // ========================================
  // 15️⃣ CREATE ROOT WALLETS
  // ========================================
  console.log('💰 Creating root wallets...');
  await prisma.rootWallet.upsert({
    where: {
      rootId_walletType: { rootId: rootUser.id, walletType: 'PRIMARY' },
    },
    update: {},
    create: {
      rootId: rootUser.id,
      balance: 0,
      currency: 'INR',
      walletType: 'PRIMARY',
      holdBalance: 0,
      availableBalance: 0,
      isActive: true,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  console.log('✅ Root wallet created');

  // ========================================
  // 16️⃣ CREATE USER WALLETS FOR ALL USERS
  // ========================================
  console.log('💳 Creating wallets for all users...');

  // Wallet for admin1
  await prisma.wallet.upsert({
    where: {
      userId_walletType: { userId: adminUser1.id, walletType: 'PRIMARY' },
    },
    update: {},
    create: {
      userId: adminUser1.id,
      balance: 100000,
      currency: 'INR',
      walletType: 'PRIMARY',
      holdBalance: 0,
      availableBalance: 100000,
      dailyLimit: 1000000,
      monthlyLimit: 10000000,
      perTransactionLimit: 500000,
      isActive: true,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  // Wallet for admin2
  await prisma.wallet.upsert({
    where: {
      userId_walletType: { userId: adminUser2.id, walletType: 'PRIMARY' },
    },
    update: {},
    create: {
      userId: adminUser2.id,
      balance: 100000,
      currency: 'INR',
      walletType: 'PRIMARY',
      holdBalance: 0,
      availableBalance: 100000,
      dailyLimit: 1000000,
      monthlyLimit: 10000000,
      perTransactionLimit: 500000,
      isActive: true,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  // Wallet for state head 1
  await prisma.wallet.upsert({
    where: {
      userId_walletType: { userId: stateHeadUser1.id, walletType: 'PRIMARY' },
    },
    update: {},
    create: {
      userId: stateHeadUser1.id,
      balance: 50000,
      currency: 'INR',
      walletType: 'PRIMARY',
      holdBalance: 0,
      availableBalance: 50000,
      dailyLimit: 500000,
      monthlyLimit: 3000000,
      perTransactionLimit: 200000,
      isActive: true,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  // Wallet for state head 2
  await prisma.wallet.upsert({
    where: {
      userId_walletType: { userId: stateHeadUser2.id, walletType: 'PRIMARY' },
    },
    update: {},
    create: {
      userId: stateHeadUser2.id,
      balance: 50000,
      currency: 'INR',
      walletType: 'PRIMARY',
      holdBalance: 0,
      availableBalance: 50000,
      dailyLimit: 500000,
      monthlyLimit: 3000000,
      perTransactionLimit: 200000,
      isActive: true,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
  });

  // Wallets for Master Distributors
  const masterDistributors = [
    { user: masterDistributorUser1, name: 'Master Distributor 1' },
    { user: masterDistributorUser2, name: 'Master Distributor 2' },
    { user: masterDistributorUserA, name: 'Master Distributor A' },
    { user: masterDistributorUserX, name: 'Master Distributor X' },
  ];

  for (const { user } of masterDistributors) {
    await prisma.wallet.upsert({
      where: {
        userId_walletType: { userId: user.id, walletType: 'PRIMARY' },
      },
      update: {},
      create: {
        userId: user.id,
        balance: 25000,
        currency: 'INR',
        walletType: 'PRIMARY',
        holdBalance: 0,
        availableBalance: 25000,
        dailyLimit: 250000,
        monthlyLimit: 1500000,
        perTransactionLimit: 100000,
        isActive: true,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
      },
    });
  }

  // Wallets for Distributors
  const distributors = [
    { user: distributorUser1, name: 'Distributor 1' },
    { user: distributorUser2, name: 'Distributor 2' },
    { user: distributorUserA1, name: 'Distributor A1' },
    { user: distributorUserB, name: 'Distributor B' },
    { user: distributorUserY, name: 'Distributor Y' },
  ];

  for (const { user } of distributors) {
    await prisma.wallet.upsert({
      where: {
        userId_walletType: { userId: user.id, walletType: 'PRIMARY' },
      },
      update: {},
      create: {
        userId: user.id,
        balance: 10000,
        currency: 'INR',
        walletType: 'PRIMARY',
        holdBalance: 0,
        availableBalance: 10000,
        dailyLimit: 100000,
        monthlyLimit: 500000,
        perTransactionLimit: 50000,
        isActive: true,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
      },
    });
  }

  // Wallets for Retailers
  const retailers = [
    { user: retailerUser1, name: 'Retailer 1' },
    { user: retailerUser2, name: 'Retailer 2' },
    { user: retailerUserA1, name: 'Retailer A1' },
    { user: retailerUserB1, name: 'Retailer B1' },
    { user: retailerUserC, name: 'Retailer C' },
    { user: retailerUserZ, name: 'Retailer Z' },
  ];

  for (const { user } of retailers) {
    await prisma.wallet.upsert({
      where: {
        userId_walletType: { userId: user.id, walletType: 'PRIMARY' },
      },
      update: {},
      create: {
        userId: user.id,
        balance: 5000,
        currency: 'INR',
        walletType: 'PRIMARY',
        holdBalance: 0,
        availableBalance: 5000,
        dailyLimit: 50000,
        monthlyLimit: 200000,
        perTransactionLimit: 25000,
        isActive: true,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
      },
    });
  }

  console.log('✅ All wallets created');

  // ========================================
  // 17️⃣ CREATE IP WHITELISTS ONLY FOR ROOT AND ADMINS
  // ========================================
  console.log('🌐 Creating IP whitelists ONLY for Root and Admins...');

  // Root IP whitelist
  await prisma.ipWhitelist.upsert({
    where: { domainName: 'http://localhost:5174' },
    update: {},
    create: {
      domainName: 'http://localhost:5174',
      serverIp: '127.0.0.1',
      rootId: rootUser.id,
      userId: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  // Admin1 IP whitelist
  await prisma.ipWhitelist.upsert({
    where: { domainName: 'http://localhost:5173' },
    update: {},
    create: {
      domainName: 'http://localhost:5173',
      serverIp: '127.0.0.1',
      rootId: null,
      userId: adminUser1.id,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  // Admin2 IP whitelist
  await prisma.ipWhitelist.upsert({
    where: { domainName: 'http://localhost:5175' },
    update: {},
    create: {
      domainName: 'http://localhost:5175',
      serverIp: '127.0.0.1',
      rootId: null,
      userId: adminUser2.id,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  console.log('✅ IP whitelists created ONLY for Root and Admins');
  console.log(
    '   ❌ State Heads, Distributors, Retailers के लिए कोई IP whitelist नहीं बनाई गई',
  );

  // ========================================
  // 🎯 DEBUG: Verify the hierarchy
  // ========================================
  console.log('\n🔍 Verifying hierarchy...');

  const usersToVerify = [
    { user: stateHeadUser1, name: 'First State Head' },
    { user: stateHeadUser2, name: 'Second State Head' },
    { user: masterDistributorUser1, name: 'Master Distributor 1' },
    { user: masterDistributorUser2, name: 'Master Distributor 2' },
    {
      user: masterDistributorUserA,
      name: 'Master Distributor A (direct under Admin1)',
    },
    {
      user: masterDistributorUserX,
      name: 'Master Distributor X (direct under Admin2)',
    },
    { user: distributorUser1, name: 'Distributor 1' },
    { user: distributorUser2, name: 'Distributor 2' },
    { user: distributorUserB, name: 'Distributor B (direct under Admin1)' },
    { user: distributorUserY, name: 'Distributor Y (direct under Admin2)' },
    { user: retailerUser1, name: 'Retailer 1' },
    { user: retailerUser2, name: 'Retailer 2' },
    { user: retailerUserC, name: 'Retailer C (direct under Admin1)' },
    { user: retailerUserZ, name: 'Retailer Z (direct under Admin2)' },
  ];

  for (const { user, name } of usersToVerify) {
    const verifyUser = await prisma.user.findUnique({
      where: { id: user.id },
      include: {
        role: true,
        parent: {
          include: {
            role: true,
          },
        },
      },
    });

    if (verifyUser) {
      console.log(`\n${name} Info:`);
      console.log(`- Username: ${verifyUser.username}`);
      console.log(`- Role: ${verifyUser.role.name}`);
      console.log(`- Hierarchy Level: ${verifyUser.hierarchyLevel}`);

      if (verifyUser.parent) {
        console.log(`- Parent: ${verifyUser.parent.username}`);
        console.log(
          `- Parent Role: ${verifyUser.parent.role?.name || 'No role found'}`,
        );

        const parentLevel = verifyUser.parent.hierarchyLevel || 0;
        const childLevel = verifyUser.hierarchyLevel;

        const willFail = parentLevel >= childLevel;
        console.log(`Result: ${willFail ? '❌ ERROR' : '✅ OK'}`);

        if (!willFail) {
          console.log('✅ Hierarchy is VALID for login!');
        }
      }
    }
  }

  // ========================================
  // 📊 SUMMARY
  // ========================================
  console.log('\n🎉 Seed Completed Successfully!\n');
  console.log('====================================');
  console.log('SYSTEM USERS SUMMARY:');
  console.log('====================================');
  console.log(`Total Users Created: ${19}`);
  console.log(`- Root: 1`);
  console.log(`- Admins: 2`);
  console.log(`- State Heads: 2`);
  console.log(`- Master Distributors: 4`);
  console.log(`- Distributors: 5`);
  console.log(`- Retailers: 6`);
  console.log('');

  console.log('====================================');
  console.log('HIERARCHY STRUCTURE:');
  console.log('====================================');
  console.log(`Root (Level 0)`);
  console.log(`├── Admin1 (Level 1)`);
  console.log(`│   ├── State Head1 (Level 2)`);
  console.log(`│   │   └── Master Distributor1 (Level 3)`);
  console.log(`│   │       └── Distributor1 (Level 4)`);
  console.log(`│   │           └── Retailer1 (Level 5)`);
  console.log(`│   │`);
  console.log(`│   ├── (Direct) Master Distributor A (Level 3)`);
  console.log(`│   │       └── Distributor A1 (Level 4)`);
  console.log(`│   │            └── Retailer A1 (Level 5)`);
  console.log(`│   │`);
  console.log(`│   ├── (Direct) Distributor B (Level 4)`);
  console.log(`│   │       └── Retailer B1 (Level 5)`);
  console.log(`│   │`);
  console.log(`│   └── (Direct) Retailer C (Level 5)`);
  console.log(`│`);
  console.log(`└── Admin2 (Level 1)`);
  console.log(`    ├── State Head2 (Level 2)`);
  console.log(`    │   └── Master Distributor2 (Level 3)`);
  console.log(`    │       └── Distributor2 (Level 4)`);
  console.log(`    │           └── Retailer2 (Level 5)`);
  console.log(`    │`);
  console.log(`    ├── (Direct) Master Distributor X (Level 3)`);
  console.log(`    ├── (Direct) Distributor Y (Level 4)`);
  console.log(`    └── (Direct) Retailer Z (Level 5)`);
  console.log('');

  console.log('====================================');
  console.log('IP WHITELISTING STATUS:');
  console.log('====================================');
  console.log('✅ Whitelisted:');
  console.log('   - Root: http://localhost:5174');
  console.log('   - Admin1: http://localhost:5173');
  console.log('   - Admin2: http://localhost:5175');
  console.log('');
  console.log('❌ NOT Whitelisted (No IP restrictions):');
  console.log('   - All State Heads');
  console.log('   - All Master Distributors');
  console.log('   - All Distributors');
  console.log('   - All Retailers');
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
  console.log('- Distributor2: "Distributor2@123"');
  console.log('- Distributor A1: "DistributorA1@123"');
  console.log('- Distributor B: "DistributorB@123"');
  console.log('- Distributor Y: "DistributorY@123"');
  console.log('- Retailer1: "Retailer1@123"');
  console.log('- Retailer2: "Retailer2@123"');
  console.log('- Retailer A1: "RetailerA1@123"');
  console.log('- Retailer B1: "RetailerB1@123"');
  console.log('- Retailer C: "RetailerC@123"');
  console.log('- Retailer Z: "RetailerZ@123"');
  console.log('');

  console.log('====================================');
  console.log('Wallet Balances:');
  console.log('====================================');
  console.log('- Admin1 & Admin2: ₹100,000');
  console.log('- State Heads: ₹50,000');
  console.log('- Master Distributors: ₹25,000');
  console.log('- Distributors: ₹10,000');
  console.log('- Retailers: ₹5,000');
  console.log('');

  console.log('====================================');
  console.log('Access URLs:');
  console.log('====================================');
  console.log('✅ WITH IP WHITELISTING:');
  console.log('- Root Panel: http://localhost:5174');
  console.log('- Admin1 Panel: http://localhost:5173');
  console.log('- Admin2 Panel: http://localhost:5175');
  console.log('');
  console.log('✅ WITHOUT IP WHITELISTING (Access from anywhere):');
  console.log('- State Heads: Can access from any IP');
  console.log('- Master Distributors: Can access from any IP');
  console.log('- Distributors: Can access from any IP');
  console.log('- Retailers: Can access from any IP');
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
