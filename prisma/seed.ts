import { PrismaClient, UserRole } from '../src/generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import * as bcrypt from 'bcrypt';

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL,
});

const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('🌱 Starting database seed...');

  // Hash password helper
  const hashPassword = async (password: string) => {
    return bcrypt.hash(password, 10);
  };

  // Clear existing data
  console.log('🗑️  Clearing existing data...');
  await prisma.user.deleteMany();

  // Create Admin User
  console.log('👤 Creating admin user...');
  const admin = await prisma.user.create({
    data: {
      email: 'admin@example.com',
      password: await hashPassword('Admin123!'),
      firstName: 'Admin',
      lastName: 'User',
      role: UserRole.ADMIN,
      isActive: true,
      mustChangePassword: false,
      lastLoginAt: new Date(),
    },
  });

  // Create Instructors
  console.log('👨‍🏫 Creating instructors...');
  const instructor1 = await prisma.user.create({
    data: {
      email: 'maria.silva@example.com',
      password: await hashPassword('Instructor123!'),
      firstName: 'Maria',
      lastName: 'Silva',
      role: UserRole.INSTRUCTOR,
      isActive: true,
      mustChangePassword: false,
      createdById: admin.id,
      lastLoginAt: new Date(),
    },
  });

  const instructor2 = await prisma.user.create({
    data: {
      email: 'carlos.santos@example.com',
      password: await hashPassword('Instructor123!'),
      firstName: 'Carlos',
      lastName: 'Santos',
      role: UserRole.INSTRUCTOR,
      isActive: true,
      mustChangePassword: false,
      createdById: admin.id,
      lastLoginAt: new Date(),
    },
  });

  const instructor3 = await prisma.user.create({
    data: {
      email: 'ana.costa@example.com',
      password: await hashPassword('Instructor123!'),
      firstName: 'Ana',
      lastName: 'Costa',
      role: UserRole.INSTRUCTOR,
      isActive: true,
      mustChangePassword: true, // Must change password on first login
      createdById: admin.id,
    },
  });

  // Create Students
  console.log('👨‍🎓 Creating students...');
  const student1 = await prisma.user.create({
    data: {
      email: 'joao.oliveira@example.com',
      password: await hashPassword('Student123!'),
      firstName: 'João',
      lastName: 'Oliveira',
      role: UserRole.STUDENT,
      isActive: true,
      mustChangePassword: false,
      createdById: admin.id,
      lastLoginAt: new Date(),
    },
  });

  const student2 = await prisma.user.create({
    data: {
      email: 'patricia.ferreira@example.com',
      password: await hashPassword('Student123!'),
      firstName: 'Patrícia',
      lastName: 'Ferreira',
      role: UserRole.STUDENT,
      isActive: true,
      mustChangePassword: false,
      createdById: admin.id,
      lastLoginAt: new Date(),
    },
  });

  const student3 = await prisma.user.create({
    data: {
      email: 'lucas.almeida@example.com',
      password: await hashPassword('Student123!'),
      firstName: 'Lucas',
      lastName: 'Almeida',
      role: UserRole.STUDENT,
      isActive: true,
      mustChangePassword: true, // Must change password on first login
      createdById: instructor1.id,
    },
  });

  const student4 = await prisma.user.create({
    data: {
      email: 'fernanda.rocha@example.com',
      password: await hashPassword('Student123!'),
      firstName: 'Fernanda',
      lastName: 'Rocha',
      role: UserRole.STUDENT,
      isActive: false, // Inactive student
      mustChangePassword: false,
      createdById: admin.id,
    },
  });

  const student5 = await prisma.user.create({
    data: {
      email: 'ricardo.lima@example.com',
      password: await hashPassword('Student123!'),
      firstName: 'Ricardo',
      lastName: 'Lima',
      role: UserRole.STUDENT,
      isActive: true,
      mustChangePassword: false,
      createdById: instructor2.id,
      lastLoginAt: new Date(),
    },
  });

  console.log('✅ Seed completed successfully!');
  console.log('\n📋 Created Users:');
  console.log('  Admin:');
  console.log(`    - ${admin.email} (password: Admin123!)`);
  console.log('  Instructors:');
  console.log(`    - ${instructor1.email} (password: Instructor123!)`);
  console.log(`    - ${instructor2.email} (password: Instructor123!)`);
  console.log(
    `    - ${instructor3.email} (password: Instructor123!) [Must change password]`,
  );
  console.log('  Students:');
  console.log(`    - ${student1.email} (password: Student123!)`);
  console.log(`    - ${student2.email} (password: Student123!)`);
  console.log(
    `    - ${student3.email} (password: Student123!) [Must change password]`,
  );
  console.log(`    - ${student4.email} (password: Student123!) [Inactive]`);
  console.log(`    - ${student5.email} (password: Student123!)`);
}

main()
  .catch((e) => {
    console.error('❌ Error during seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
