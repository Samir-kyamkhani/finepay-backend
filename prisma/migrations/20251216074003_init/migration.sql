-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'DELETED');

-- CreateEnum
CREATE TYPE "EmployeeStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "CreatorType" AS ENUM ('USER', 'EMPLOYEE');

-- CreateEnum
CREATE TYPE "VerifiedByType" AS ENUM ('USER', 'EMPLOYEE');

-- CreateEnum
CREATE TYPE "BankAccountType" AS ENUM ('PERSONAL', 'BUSINESS');

-- CreateEnum
CREATE TYPE "CommissionType" AS ENUM ('FLAT', 'PERCENTAGE');

-- CreateEnum
CREATE TYPE "TransactionStatus" AS ENUM ('PENDING', 'SUCCESS', 'FAILED', 'REVERSED', 'REFUNDED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "CommissionStatus" AS ENUM ('PENDING', 'PROCESSED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "CommissionScope" AS ENUM ('ROLE', 'USER');

-- CreateEnum
CREATE TYPE "LedgerEntryType" AS ENUM ('DEBIT', 'CREDIT');

-- CreateEnum
CREATE TYPE "ReferenceType" AS ENUM ('TRANSACTION', 'COMMISSION', 'REFUND', 'ADJUSTMENT', 'BONUS', 'CHARGE', 'FEE', 'TAX', 'PAYOUT', 'COLLECTION');

-- CreateEnum
CREATE TYPE "Currency" AS ENUM ('INR');

-- CreateEnum
CREATE TYPE "WalletType" AS ENUM ('PRIMARY', 'COMMISSION', 'ESCROW', 'TAX', 'BONUS', 'HOLDING');

-- CreateEnum
CREATE TYPE "PaymentType" AS ENUM ('COLLECTION', 'PAYOUT', 'REFUND', 'REVERSAL', 'COMMISSION', 'FEE', 'TAX', 'ADJUSTMENT', 'CHARGE', 'FUND_REQ_BANK', 'FUND_REQ_RAZORPAY');

-- CreateEnum
CREATE TYPE "UserGender" AS ENUM ('MALE', 'FEMALE', 'OTHER');

-- CreateEnum
CREATE TYPE "KycStatus" AS ENUM ('UNDER_REVIEW', 'PENDING', 'VERIFIED', 'REJECTED', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "UserKycStatus" AS ENUM ('UNDER_REVIEW', 'PENDING', 'VERIFIED', 'REJECTED', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "UserKycType" AS ENUM ('AEPS', 'USER_KYC');

-- CreateEnum
CREATE TYPE "RoleType" AS ENUM ('PROPRIETOR', 'PARTNER', 'DIRECTOR');

-- CreateEnum
CREATE TYPE "BusinessType" AS ENUM ('PROPRIETORSHIP', 'PARTNERSHIP', 'PRIVATE_LIMITED');

-- CreateEnum
CREATE TYPE "EntityStatus" AS ENUM ('PENDING', 'VERIFIED', 'REJECTED', 'SUSPENDED', 'INACTIVE');

-- CreateEnum
CREATE TYPE "ProviderType" AS ENUM ('BULKPE', 'PAYTM', 'RAZORPAY', 'CCAVENUE', 'BILLDESK', 'AIRTEL', 'JIO', 'OTHER');

-- CreateEnum
CREATE TYPE "WebhookProvider" AS ENUM ('BULKPE', 'PAYTM', 'RAZORPAY', 'CCAVENUE', 'BILLDESK', 'AIRTEL', 'JIO', 'OTHER');

-- CreateEnum
CREATE TYPE "WebhookStatus" AS ENUM ('PENDING', 'PROCESSED', 'FAILED', 'RETRY');

-- CreateEnum
CREATE TYPE "ServiceStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "AssignedByType" AS ENUM ('USER');

-- CreateEnum
CREATE TYPE "BankDetailStatus" AS ENUM ('PENDING', 'VERIFIED', 'REJECTED');

-- CreateEnum
CREATE TYPE "RefundStatus" AS ENUM ('PENDING', 'PROCESSED', 'FAILED', 'CANCELLED', 'SUCCESS');

-- CreateEnum
CREATE TYPE "AuditStatus" AS ENUM ('SUCCESS', 'FAILED', 'PENDING');

-- CreateEnum
CREATE TYPE "PermissionTargetType" AS ENUM ('ROLE', 'USER', 'DEPARTMENT', 'EMPLOYEE');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "customer_id" VARCHAR(8) NOT NULL,
    "first_name" TEXT NOT NULL,
    "last_name" TEXT NOT NULL,
    "profile_image" TEXT,
    "email" TEXT NOT NULL,
    "phone_number" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "transaction_pin" TEXT,
    "hierarchy_level" INTEGER NOT NULL DEFAULT 0,
    "hierarchy_path" TEXT NOT NULL,
    "status" "UserStatus" NOT NULL DEFAULT 'INACTIVE',
    "is_kyc_verified" BOOLEAN NOT NULL DEFAULT false,
    "role_id" TEXT NOT NULL,
    "refresh_token" TEXT,
    "password_reset_token" TEXT,
    "password_reset_expires" TIMESTAMP(3),
    "email_verification_token" TEXT,
    "email_verified_at" TIMESTAMP(3),
    "email_verification_token_expires" TIMESTAMP(3),
    "last_login_at" TIMESTAMP(3),
    "last_login_ip" INET,
    "last_login_origin" TEXT,
    "action_reason" TEXT,
    "actioned_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),
    "parent_id" TEXT,
    "business_kyc_id" TEXT,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "employees" (
    "id" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "first_name" TEXT NOT NULL,
    "last_name" TEXT NOT NULL,
    "profile_image" TEXT,
    "email" TEXT NOT NULL,
    "phone_number" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "department_id" TEXT NOT NULL,
    "status" "EmployeeStatus" NOT NULL DEFAULT 'ACTIVE',
    "refresh_token" TEXT,
    "password_reset_token" TEXT,
    "password_reset_expires" TIMESTAMP(3),
    "last_login_at" TIMESTAMP(3),
    "last_login_ip" INET,
    "last_login_origin" TEXT,
    "action_reason" TEXT,
    "actioned_at" TIMESTAMP(3) NOT NULL,
    "created_by_user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "employees_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "permissions" (
    "id" TEXT NOT NULL,
    "resource" VARCHAR(200) NOT NULL,
    "action" VARCHAR(200) NOT NULL,
    "description" TEXT,
    "target_type" "PermissionTargetType" NOT NULL,
    "role_id" TEXT,
    "user_id" TEXT,
    "department_id" TEXT,
    "employee_id" TEXT,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "assigned_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked_at" TIMESTAMP(3),
    "assigned_by_type" "CreatorType" NOT NULL,
    "assigned_by_user_id" TEXT,
    "assigned_by_employee_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "permissions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "wallets" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "balance" DECIMAL(20,2) NOT NULL DEFAULT 0,
    "currency" "Currency" NOT NULL DEFAULT 'INR',
    "wallet_type" "WalletType" NOT NULL DEFAULT 'PRIMARY',
    "hold_balance" DECIMAL(20,2) NOT NULL DEFAULT 0,
    "available_balance" DECIMAL(20,2) NOT NULL DEFAULT 0,
    "daily_limit" DECIMAL(20,2),
    "monthly_limit" DECIMAL(20,2),
    "per_transaction_limit" DECIMAL(20,2),
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "wallets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "transactions" (
    "id" TEXT NOT NULL,
    "reference_id" VARCHAR(50),
    "external_ref_id" VARCHAR(100),
    "idempotency_key" VARCHAR(255),
    "amount" DECIMAL(20,2) NOT NULL,
    "currency" "Currency" NOT NULL DEFAULT 'INR',
    "net_amount" DECIMAL(20,2) NOT NULL,
    "status" "TransactionStatus" NOT NULL DEFAULT 'PENDING',
    "service_id" TEXT,
    "payment_type" "PaymentType" NOT NULL,
    "user_id" TEXT NOT NULL,
    "wallet_id" TEXT NOT NULL,
    "api_entity_id" TEXT,
    "total_commission" DECIMAL(20,2) NOT NULL DEFAULT 0,
    "provider_charge" DECIMAL(20,2),
    "tax_amount" DECIMAL(20,2),
    "fee_amount" DECIMAL(20,2),
    "cashback_amount" DECIMAL(20,2),
    "provider_reference" VARCHAR(100),
    "provider_response" JSON,
    "request_payload" JSON,
    "response_payload" JSON,
    "initiated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processed_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),

    CONSTRAINT "transactions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "commission_earnings" (
    "id" TEXT NOT NULL,
    "transaction_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "from_user_id" TEXT,
    "amount" DECIMAL(20,2) NOT NULL,
    "commission_amount" DECIMAL(20,2) NOT NULL,
    "commission_type" "CommissionType" NOT NULL,
    "tds_amount" DECIMAL(20,2),
    "gst_amount" DECIMAL(20,2),
    "net_amount" DECIMAL(20,2) NOT NULL,
    "status" "CommissionStatus" NOT NULL DEFAULT 'PENDING',
    "metadata" JSON,
    "processed_at" TIMESTAMP(3),
    "cancelled_at" TIMESTAMP(3),
    "failure_reason" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "commission_earnings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "bank_details" (
    "id" TEXT NOT NULL,
    "account_holder" VARCHAR(100) NOT NULL,
    "account_number" VARCHAR(18) NOT NULL,
    "phone_number" VARCHAR(15) NOT NULL,
    "account_type" "BankAccountType" NOT NULL,
    "ifsc_code" VARCHAR(11) NOT NULL,
    "bank_name" VARCHAR(100) NOT NULL,
    "bank_rejection_reason" TEXT,
    "bank_proof_file" VARCHAR(500) NOT NULL,
    "status" "BankDetailStatus" NOT NULL DEFAULT 'PENDING',
    "is_primary" BOOLEAN NOT NULL DEFAULT false,
    "user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "bank_details_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ledger_entries" (
    "id" TEXT NOT NULL,
    "transaction_id" TEXT,
    "wallet_id" TEXT NOT NULL,
    "entry_type" "LedgerEntryType" NOT NULL,
    "reference_type" "ReferenceType" NOT NULL,
    "service_id" TEXT,
    "amount" DECIMAL(20,2) NOT NULL,
    "running_balance" DECIMAL(20,2) NOT NULL,
    "narration" VARCHAR(500) NOT NULL,
    "metadata" JSON,
    "idempotency_key" VARCHAR(255) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ledger_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "commission_settings" (
    "id" TEXT NOT NULL,
    "scope" "CommissionScope" NOT NULL,
    "role_id" TEXT,
    "target_user_id" TEXT,
    "service_id" TEXT,
    "commission_type" "CommissionType",
    "commission_value" DECIMAL(12,4),
    "surcharge_type" "CommissionType",
    "surcharge_value" DECIMAL(12,4),
    "min_amount" DECIMAL(20,2),
    "max_amount" DECIMAL(20,2),
    "apply_tds" BOOLEAN NOT NULL DEFAULT false,
    "tds_percent" DECIMAL(5,2),
    "apply_gst" BOOLEAN NOT NULL DEFAULT false,
    "gst_percent" DECIMAL(5,2),
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "effective_from" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "effective_to" TIMESTAMP(3),
    "created_by_type" "CreatorType" NOT NULL,
    "created_by_user_id" TEXT,
    "created_by_employee_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "commission_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "roles" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(50) NOT NULL,
    "description" TEXT,
    "parent_id" TEXT,
    "hierarchy_level" INTEGER NOT NULL DEFAULT 0,
    "hierarchy_path" TEXT NOT NULL,
    "is_root" BOOLEAN NOT NULL DEFAULT false,
    "permissions" JSON,
    "is_ipwhitelist" BOOLEAN NOT NULL DEFAULT false,
    "created_by_type" "CreatorType" NOT NULL,
    "created_by_user_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "departments" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(50) NOT NULL,
    "description" TEXT,
    "created_by_type" "CreatorType" NOT NULL,
    "created_by_user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "departments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "service_providers" (
    "id" TEXT NOT NULL,
    "integration_id" TEXT NOT NULL,
    "service_name" VARCHAR(100) NOT NULL,
    "status" "ServiceStatus" NOT NULL DEFAULT 'ACTIVE',
    "assigned_by_type" "AssignedByType" NOT NULL,
    "assigned_by_user_id" TEXT NOT NULL,
    "hierarchy_level" INTEGER NOT NULL DEFAULT 0,
    "hierarchy_path" TEXT NOT NULL,
    "can_reassign" BOOLEAN NOT NULL DEFAULT true,
    "user_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "service_providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_integrations" (
    "id" TEXT NOT NULL,
    "platform_name" VARCHAR(50) NOT NULL,
    "service_name" VARCHAR(50) NOT NULL,
    "api_base_url" TEXT NOT NULL,
    "credentials" JSON NOT NULL,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_by_user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "api_integrations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_kyc" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "first_name" VARCHAR(100) NOT NULL,
    "last_name" VARCHAR(100) NOT NULL,
    "father_name" VARCHAR(100) NOT NULL,
    "dob" TIMESTAMP(3) NOT NULL,
    "gender" "UserGender" NOT NULL,
    "status" "UserKycStatus" NOT NULL DEFAULT 'PENDING',
    "type" "UserKycType" NOT NULL DEFAULT 'USER_KYC',
    "kyc_rejection_reason" TEXT,
    "address_id" TEXT NOT NULL,
    "pan_file" VARCHAR(500) NOT NULL,
    "aadhaar_file" VARCHAR(500) NOT NULL,
    "address_proof_file" VARCHAR(500) NOT NULL,
    "photo" VARCHAR(500) NOT NULL,
    "role_type" "RoleType" NOT NULL DEFAULT 'PROPRIETOR',
    "business_kyc_id" TEXT,
    "verified_by_type" TEXT,
    "verified_by_user_id" TEXT,
    "verified_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "user_kyc_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "business_kycs" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "business_name" VARCHAR(200) NOT NULL,
    "business_type" "BusinessType" NOT NULL,
    "status" "KycStatus" NOT NULL DEFAULT 'PENDING',
    "rejection_reason" TEXT,
    "address_id" TEXT NOT NULL,
    "pan_file" VARCHAR(500) NOT NULL,
    "gst_file" VARCHAR(500) NOT NULL,
    "br_doc" VARCHAR(500),
    "partnership_deed" VARCHAR(500),
    "partner_kyc_numbers" INTEGER,
    "cin" VARCHAR(25),
    "moa_file" VARCHAR(500),
    "aoa_file" VARCHAR(500),
    "authorized_member_count" INTEGER NOT NULL,
    "director_shareholding_file" VARCHAR(500),
    "verified_by_type" TEXT,
    "verified_by_user_id" TEXT,
    "verified_by_employee_id" TEXT,
    "verified_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "business_kycs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "states" (
    "id" TEXT NOT NULL,
    "state_name" VARCHAR(100) NOT NULL,
    "state_code" VARCHAR(10) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "states_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cities" (
    "id" TEXT NOT NULL,
    "city_name" VARCHAR(100) NOT NULL,
    "city_code" VARCHAR(10) NOT NULL,
    "state_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "cities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "addresses" (
    "id" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "pin_code" VARCHAR(10) NOT NULL,
    "state_id" TEXT NOT NULL,
    "city_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "addresses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_entities" (
    "id" TEXT NOT NULL,
    "entity_type" VARCHAR(50) NOT NULL,
    "entity_id" VARCHAR(100) NOT NULL,
    "reference" VARCHAR(100),
    "user_id" TEXT NOT NULL,
    "service_id" TEXT,
    "status" "EntityStatus" NOT NULL DEFAULT 'PENDING',
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "provider" "ProviderType" NOT NULL,
    "provider_data" JSON,
    "metadata" JSON,
    "verification_data" JSON,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "verified_at" TIMESTAMP(3),

    CONSTRAINT "api_entities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_webhooks" (
    "id" TEXT NOT NULL,
    "transaction_id" TEXT,
    "api_entity_id" TEXT NOT NULL,
    "provider" "WebhookProvider" NOT NULL,
    "event_type" VARCHAR(100) NOT NULL,
    "payload" JSON NOT NULL,
    "signature" VARCHAR(500),
    "headers" JSON,
    "status" "WebhookStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_attempt_at" TIMESTAMP(3),
    "response" JSON,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "api_webhooks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ip_whitelists" (
    "id" TEXT NOT NULL,
    "domain_name" VARCHAR(255) NOT NULL,
    "server_ip" INET NOT NULL,
    "user_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ip_whitelists_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system_settings" (
    "id" TEXT NOT NULL,
    "companyName" TEXT,
    "companyLogo" TEXT,
    "favIcon" TEXT,
    "phoneNumber" TEXT,
    "whatsappNumber" TEXT,
    "companyEmail" TEXT,
    "facebookUrl" TEXT,
    "instagramUrl" TEXT,
    "twitterUrl" TEXT,
    "linkedinUrl" TEXT,
    "websiteUrl" TEXT,
    "settings" JSONB,
    "userId" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "system_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pii_consents" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "user_kyc_id" TEXT,
    "business_kyc_id" TEXT,
    "piiType" VARCHAR(50) NOT NULL,
    "piiHash" VARCHAR(64) NOT NULL,
    "provided_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "scope" VARCHAR(50) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pii_consents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "refunds" (
    "id" TEXT NOT NULL,
    "transaction_id" TEXT NOT NULL,
    "initiated_by" VARCHAR(100) NOT NULL,
    "amount" DECIMAL(20,2) NOT NULL,
    "status" "RefundStatus" NOT NULL DEFAULT 'PENDING',
    "reason" VARCHAR(500),
    "metadata" JSON,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "refunds_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "idempotency_keys" (
    "key" VARCHAR(255) NOT NULL,
    "user_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "meta" JSON,

    CONSTRAINT "idempotency_keys_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" TEXT NOT NULL,
    "performer_type" TEXT NOT NULL,
    "performer_id" TEXT NOT NULL,
    "target_user_type" TEXT NOT NULL,
    "target_user_id" TEXT NOT NULL,
    "action" VARCHAR(100) NOT NULL,
    "description" TEXT NOT NULL,
    "resource_type" VARCHAR(50) NOT NULL,
    "resource_id" TEXT NOT NULL,
    "old_data" JSON,
    "new_data" JSON,
    "status" "AuditStatus" NOT NULL,
    "ip_address" INET,
    "user_agent" TEXT,
    "metadata" JSON,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_customer_id_key" ON "users"("customer_id");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_phone_number_key" ON "users"("phone_number");

-- CreateIndex
CREATE INDEX "users_parent_id_idx" ON "users"("parent_id");

-- CreateIndex
CREATE INDEX "users_hierarchy_level_idx" ON "users"("hierarchy_level");

-- CreateIndex
CREATE INDEX "users_hierarchy_path_idx" ON "users"("hierarchy_path");

-- CreateIndex
CREATE INDEX "users_role_id_idx" ON "users"("role_id");

-- CreateIndex
CREATE INDEX "users_customer_id_idx" ON "users"("customer_id");

-- CreateIndex
CREATE INDEX "users_business_kyc_id_idx" ON "users"("business_kyc_id");

-- CreateIndex
CREATE INDEX "users_email_idx" ON "users"("email");

-- CreateIndex
CREATE INDEX "users_phone_number_idx" ON "users"("phone_number");

-- CreateIndex
CREATE INDEX "users_deleted_at_idx" ON "users"("deleted_at");

-- CreateIndex
CREATE UNIQUE INDEX "employees_username_key" ON "employees"("username");

-- CreateIndex
CREATE UNIQUE INDEX "employees_email_key" ON "employees"("email");

-- CreateIndex
CREATE UNIQUE INDEX "employees_phone_number_key" ON "employees"("phone_number");

-- CreateIndex
CREATE INDEX "employees_department_id_idx" ON "employees"("department_id");

-- CreateIndex
CREATE INDEX "employees_created_by_user_id_idx" ON "employees"("created_by_user_id");

-- CreateIndex
CREATE INDEX "employees_email_idx" ON "employees"("email");

-- CreateIndex
CREATE INDEX "employees_phone_number_idx" ON "employees"("phone_number");

-- CreateIndex
CREATE INDEX "permissions_resource_action_idx" ON "permissions"("resource", "action");

-- CreateIndex
CREATE INDEX "permissions_target_type_idx" ON "permissions"("target_type");

-- CreateIndex
CREATE INDEX "permissions_role_id_idx" ON "permissions"("role_id");

-- CreateIndex
CREATE INDEX "permissions_user_id_idx" ON "permissions"("user_id");

-- CreateIndex
CREATE INDEX "permissions_department_id_idx" ON "permissions"("department_id");

-- CreateIndex
CREATE INDEX "permissions_employee_id_idx" ON "permissions"("employee_id");

-- CreateIndex
CREATE INDEX "permissions_is_active_idx" ON "permissions"("is_active");

-- CreateIndex
CREATE INDEX "permissions_assigned_by_user_id_idx" ON "permissions"("assigned_by_user_id");

-- CreateIndex
CREATE UNIQUE INDEX "permissions_resource_action_target_type_role_id_user_id_dep_key" ON "permissions"("resource", "action", "target_type", "role_id", "user_id", "department_id", "employee_id");

-- CreateIndex
CREATE INDEX "wallets_user_id_idx" ON "wallets"("user_id");

-- CreateIndex
CREATE INDEX "wallets_wallet_type_idx" ON "wallets"("wallet_type");

-- CreateIndex
CREATE INDEX "wallets_is_active_idx" ON "wallets"("is_active");

-- CreateIndex
CREATE INDEX "wallets_created_at_idx" ON "wallets"("created_at");

-- CreateIndex
CREATE INDEX "wallets_balance_idx" ON "wallets"("balance");

-- CreateIndex
CREATE INDEX "wallets_deleted_at_idx" ON "wallets"("deleted_at");

-- CreateIndex
CREATE UNIQUE INDEX "wallets_user_id_wallet_type_key" ON "wallets"("user_id", "wallet_type");

-- CreateIndex
CREATE UNIQUE INDEX "transactions_reference_id_key" ON "transactions"("reference_id");

-- CreateIndex
CREATE UNIQUE INDEX "transactions_idempotency_key_key" ON "transactions"("idempotency_key");

-- CreateIndex
CREATE INDEX "transactions_user_id_idx" ON "transactions"("user_id");

-- CreateIndex
CREATE INDEX "transactions_wallet_id_idx" ON "transactions"("wallet_id");

-- CreateIndex
CREATE INDEX "transactions_service_id_idx" ON "transactions"("service_id");

-- CreateIndex
CREATE INDEX "transactions_api_entity_id_idx" ON "transactions"("api_entity_id");

-- CreateIndex
CREATE INDEX "transactions_initiated_at_idx" ON "transactions"("initiated_at");

-- CreateIndex
CREATE INDEX "transactions_status_initiated_at_idx" ON "transactions"("status", "initiated_at");

-- CreateIndex
CREATE INDEX "transactions_payment_type_idx" ON "transactions"("payment_type");

-- CreateIndex
CREATE INDEX "transactions_processed_at_idx" ON "transactions"("processed_at");

-- CreateIndex
CREATE INDEX "transactions_completed_at_idx" ON "transactions"("completed_at");

-- CreateIndex
CREATE INDEX "transactions_external_ref_id_idx" ON "transactions"("external_ref_id");

-- CreateIndex
CREATE INDEX "transactions_provider_reference_idx" ON "transactions"("provider_reference");

-- CreateIndex
CREATE INDEX "transactions_user_id_status_initiated_at_idx" ON "transactions"("user_id", "status", "initiated_at");

-- CreateIndex
CREATE INDEX "transactions_wallet_id_status_initiated_at_idx" ON "transactions"("wallet_id", "status", "initiated_at");

-- CreateIndex
CREATE INDEX "commission_earnings_transaction_id_user_id_idx" ON "commission_earnings"("transaction_id", "user_id");

-- CreateIndex
CREATE INDEX "commission_earnings_user_id_created_at_idx" ON "commission_earnings"("user_id", "created_at");

-- CreateIndex
CREATE INDEX "commission_earnings_from_user_id_created_at_idx" ON "commission_earnings"("from_user_id", "created_at");

-- CreateIndex
CREATE INDEX "commission_earnings_status_created_at_idx" ON "commission_earnings"("status", "created_at");

-- CreateIndex
CREATE INDEX "commission_earnings_processed_at_idx" ON "commission_earnings"("processed_at");

-- CreateIndex
CREATE INDEX "commission_earnings_cancelled_at_idx" ON "commission_earnings"("cancelled_at");

-- CreateIndex
CREATE INDEX "commission_earnings_user_id_status_created_at_idx" ON "commission_earnings"("user_id", "status", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "bank_details_account_number_key" ON "bank_details"("account_number");

-- CreateIndex
CREATE INDEX "bank_details_user_id_idx" ON "bank_details"("user_id");

-- CreateIndex
CREATE INDEX "bank_details_status_idx" ON "bank_details"("status");

-- CreateIndex
CREATE INDEX "bank_details_is_primary_idx" ON "bank_details"("is_primary");

-- CreateIndex
CREATE INDEX "bank_details_created_at_idx" ON "bank_details"("created_at");

-- CreateIndex
CREATE INDEX "bank_details_ifsc_code_idx" ON "bank_details"("ifsc_code");

-- CreateIndex
CREATE UNIQUE INDEX "bank_details_user_id_is_primary_key" ON "bank_details"("user_id", "is_primary");

-- CreateIndex
CREATE UNIQUE INDEX "ledger_entries_idempotency_key_key" ON "ledger_entries"("idempotency_key");

-- CreateIndex
CREATE INDEX "ledger_entries_transaction_id_idx" ON "ledger_entries"("transaction_id");

-- CreateIndex
CREATE INDEX "ledger_entries_wallet_id_created_at_idx" ON "ledger_entries"("wallet_id", "created_at");

-- CreateIndex
CREATE INDEX "ledger_entries_service_id_reference_type_idx" ON "ledger_entries"("service_id", "reference_type");

-- CreateIndex
CREATE INDEX "ledger_entries_entry_type_created_at_idx" ON "ledger_entries"("entry_type", "created_at");

-- CreateIndex
CREATE INDEX "ledger_entries_reference_type_created_at_idx" ON "ledger_entries"("reference_type", "created_at");

-- CreateIndex
CREATE INDEX "ledger_entries_created_at_idx" ON "ledger_entries"("created_at");

-- CreateIndex
CREATE INDEX "ledger_entries_wallet_id_entry_type_created_at_idx" ON "ledger_entries"("wallet_id", "entry_type", "created_at");

-- CreateIndex
CREATE INDEX "ledger_entries_wallet_id_running_balance_idx" ON "ledger_entries"("wallet_id", "running_balance");

-- CreateIndex
CREATE INDEX "commission_settings_scope_role_id_target_user_id_idx" ON "commission_settings"("scope", "role_id", "target_user_id");

-- CreateIndex
CREATE INDEX "commission_settings_service_id_is_active_idx" ON "commission_settings"("service_id", "is_active");

-- CreateIndex
CREATE INDEX "commission_settings_created_by_type_created_by_user_id_crea_idx" ON "commission_settings"("created_by_type", "created_by_user_id", "created_by_employee_id");

-- CreateIndex
CREATE INDEX "commission_settings_effective_from_effective_to_idx" ON "commission_settings"("effective_from", "effective_to");

-- CreateIndex
CREATE INDEX "commission_settings_scope_role_id_target_user_id_service_id_idx" ON "commission_settings"("scope", "role_id", "target_user_id", "service_id");

-- CreateIndex
CREATE UNIQUE INDEX "roles_name_key" ON "roles"("name");

-- CreateIndex
CREATE INDEX "roles_parent_id_idx" ON "roles"("parent_id");

-- CreateIndex
CREATE INDEX "roles_hierarchy_level_idx" ON "roles"("hierarchy_level");

-- CreateIndex
CREATE INDEX "roles_hierarchy_path_idx" ON "roles"("hierarchy_path");

-- CreateIndex
CREATE INDEX "roles_is_root_idx" ON "roles"("is_root");

-- CreateIndex
CREATE INDEX "roles_created_by_user_id_created_by_type_idx" ON "roles"("created_by_user_id", "created_by_type");

-- CreateIndex
CREATE INDEX "roles_name_idx" ON "roles"("name");

-- CreateIndex
CREATE INDEX "roles_hierarchy_level_hierarchy_path_idx" ON "roles"("hierarchy_level", "hierarchy_path");

-- CreateIndex
CREATE UNIQUE INDEX "departments_name_key" ON "departments"("name");

-- CreateIndex
CREATE INDEX "departments_created_by_user_id_created_by_type_idx" ON "departments"("created_by_user_id", "created_by_type");

-- CreateIndex
CREATE INDEX "departments_name_idx" ON "departments"("name");

-- CreateIndex
CREATE INDEX "service_providers_integration_id_idx" ON "service_providers"("integration_id");

-- CreateIndex
CREATE INDEX "service_providers_assigned_by_user_id_assigned_by_type_idx" ON "service_providers"("assigned_by_user_id", "assigned_by_type");

-- CreateIndex
CREATE INDEX "service_providers_hierarchy_path_idx" ON "service_providers"("hierarchy_path");

-- CreateIndex
CREATE INDEX "service_providers_status_idx" ON "service_providers"("status");

-- CreateIndex
CREATE INDEX "service_providers_hierarchy_level_idx" ON "service_providers"("hierarchy_level");

-- CreateIndex
CREATE INDEX "api_integrations_created_by_user_id_idx" ON "api_integrations"("created_by_user_id");

-- CreateIndex
CREATE INDEX "api_integrations_is_active_idx" ON "api_integrations"("is_active");

-- CreateIndex
CREATE INDEX "api_integrations_platform_name_service_name_idx" ON "api_integrations"("platform_name", "service_name");

-- CreateIndex
CREATE UNIQUE INDEX "api_integrations_platform_name_service_name_created_by_user_key" ON "api_integrations"("platform_name", "service_name", "created_by_user_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_kyc_user_id_key" ON "user_kyc"("user_id");

-- CreateIndex
CREATE INDEX "user_kyc_user_id_idx" ON "user_kyc"("user_id");

-- CreateIndex
CREATE INDEX "user_kyc_business_kyc_id_idx" ON "user_kyc"("business_kyc_id");

-- CreateIndex
CREATE INDEX "user_kyc_status_idx" ON "user_kyc"("status");

-- CreateIndex
CREATE INDEX "user_kyc_verified_by_user_id_idx" ON "user_kyc"("verified_by_user_id");

-- CreateIndex
CREATE INDEX "user_kyc_address_id_idx" ON "user_kyc"("address_id");

-- CreateIndex
CREATE INDEX "user_kyc_role_type_idx" ON "user_kyc"("role_type");

-- CreateIndex
CREATE INDEX "user_kyc_deleted_at_idx" ON "user_kyc"("deleted_at");

-- CreateIndex
CREATE INDEX "business_kycs_user_id_status_idx" ON "business_kycs"("user_id", "status");

-- CreateIndex
CREATE INDEX "business_kycs_verified_by_user_id_verified_by_employee_id_idx" ON "business_kycs"("verified_by_user_id", "verified_by_employee_id");

-- CreateIndex
CREATE INDEX "business_kycs_business_type_idx" ON "business_kycs"("business_type");

-- CreateIndex
CREATE INDEX "business_kycs_address_id_idx" ON "business_kycs"("address_id");

-- CreateIndex
CREATE UNIQUE INDEX "business_kycs_user_id_key" ON "business_kycs"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "states_state_code_key" ON "states"("state_code");

-- CreateIndex
CREATE INDEX "states_state_name_idx" ON "states"("state_name");

-- CreateIndex
CREATE INDEX "states_state_code_idx" ON "states"("state_code");

-- CreateIndex
CREATE UNIQUE INDEX "cities_city_code_key" ON "cities"("city_code");

-- CreateIndex
CREATE INDEX "cities_city_name_idx" ON "cities"("city_name");

-- CreateIndex
CREATE INDEX "cities_state_id_idx" ON "cities"("state_id");

-- CreateIndex
CREATE INDEX "cities_city_code_idx" ON "cities"("city_code");

-- CreateIndex
CREATE INDEX "addresses_city_id_idx" ON "addresses"("city_id");

-- CreateIndex
CREATE INDEX "addresses_state_id_idx" ON "addresses"("state_id");

-- CreateIndex
CREATE INDEX "addresses_pin_code_idx" ON "addresses"("pin_code");

-- CreateIndex
CREATE UNIQUE INDEX "api_entities_entity_id_key" ON "api_entities"("entity_id");

-- CreateIndex
CREATE UNIQUE INDEX "api_entities_reference_key" ON "api_entities"("reference");

-- CreateIndex
CREATE INDEX "api_entities_user_id_service_id_idx" ON "api_entities"("user_id", "service_id");

-- CreateIndex
CREATE INDEX "api_entities_entity_type_entity_id_idx" ON "api_entities"("entity_type", "entity_id");

-- CreateIndex
CREATE INDEX "api_entities_status_created_at_idx" ON "api_entities"("status", "created_at");

-- CreateIndex
CREATE INDEX "api_entities_reference_idx" ON "api_entities"("reference");

-- CreateIndex
CREATE INDEX "api_entities_is_active_status_idx" ON "api_entities"("is_active", "status");

-- CreateIndex
CREATE INDEX "api_webhooks_transaction_id_idx" ON "api_webhooks"("transaction_id");

-- CreateIndex
CREATE INDEX "api_webhooks_api_entity_id_idx" ON "api_webhooks"("api_entity_id");

-- CreateIndex
CREATE INDEX "api_webhooks_provider_event_type_idx" ON "api_webhooks"("provider", "event_type");

-- CreateIndex
CREATE INDEX "api_webhooks_status_created_at_idx" ON "api_webhooks"("status", "created_at");

-- CreateIndex
CREATE INDEX "api_webhooks_last_attempt_at_idx" ON "api_webhooks"("last_attempt_at");

-- CreateIndex
CREATE INDEX "api_webhooks_status_attempts_idx" ON "api_webhooks"("status", "attempts");

-- CreateIndex
CREATE UNIQUE INDEX "ip_whitelists_domain_name_key" ON "ip_whitelists"("domain_name");

-- CreateIndex
CREATE INDEX "ip_whitelists_domain_name_idx" ON "ip_whitelists"("domain_name");

-- CreateIndex
CREATE INDEX "ip_whitelists_user_id_idx" ON "ip_whitelists"("user_id");

-- CreateIndex
CREATE INDEX "ip_whitelists_server_ip_idx" ON "ip_whitelists"("server_ip");

-- CreateIndex
CREATE UNIQUE INDEX "system_settings_userId_key" ON "system_settings"("userId");

-- CreateIndex
CREATE INDEX "pii_consents_user_kyc_id_idx" ON "pii_consents"("user_kyc_id");

-- CreateIndex
CREATE INDEX "pii_consents_business_kyc_id_idx" ON "pii_consents"("business_kyc_id");

-- CreateIndex
CREATE INDEX "pii_consents_expires_at_idx" ON "pii_consents"("expires_at");

-- CreateIndex
CREATE INDEX "pii_consents_piiHash_idx" ON "pii_consents"("piiHash");

-- CreateIndex
CREATE UNIQUE INDEX "pii_consents_user_id_piiType_scope_key" ON "pii_consents"("user_id", "piiType", "scope");

-- CreateIndex
CREATE INDEX "refunds_transaction_id_idx" ON "refunds"("transaction_id");

-- CreateIndex
CREATE INDEX "refunds_status_created_at_idx" ON "refunds"("status", "created_at");

-- CreateIndex
CREATE INDEX "refunds_initiated_by_idx" ON "refunds"("initiated_by");

-- CreateIndex
CREATE INDEX "idempotency_keys_key_idx" ON "idempotency_keys"("key");

-- CreateIndex
CREATE INDEX "idempotency_keys_user_id_idx" ON "idempotency_keys"("user_id");

-- CreateIndex
CREATE INDEX "idempotency_keys_expires_at_idx" ON "idempotency_keys"("expires_at");

-- CreateIndex
CREATE INDEX "idempotency_keys_used_idx" ON "idempotency_keys"("used");

-- CreateIndex
CREATE INDEX "audit_logs_performer_type_performer_id_idx" ON "audit_logs"("performer_type", "performer_id");

-- CreateIndex
CREATE INDEX "audit_logs_target_user_type_target_user_id_idx" ON "audit_logs"("target_user_type", "target_user_id");

-- CreateIndex
CREATE INDEX "audit_logs_resource_type_resource_id_idx" ON "audit_logs"("resource_type", "resource_id");

-- CreateIndex
CREATE INDEX "audit_logs_status_created_at_idx" ON "audit_logs"("status", "created_at");

-- CreateIndex
CREATE INDEX "audit_logs_action_created_at_idx" ON "audit_logs"("action", "created_at");

-- CreateIndex
CREATE INDEX "audit_logs_created_at_idx" ON "audit_logs"("created_at");

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_parent_id_fkey" FOREIGN KEY ("parent_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "employees" ADD CONSTRAINT "employees_department_id_fkey" FOREIGN KEY ("department_id") REFERENCES "departments"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "employees" ADD CONSTRAINT "employees_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "permissions" ADD CONSTRAINT "permissions_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "permissions" ADD CONSTRAINT "permissions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "permissions" ADD CONSTRAINT "permissions_department_id_fkey" FOREIGN KEY ("department_id") REFERENCES "departments"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "permissions" ADD CONSTRAINT "permissions_employee_id_fkey" FOREIGN KEY ("employee_id") REFERENCES "employees"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "permissions" ADD CONSTRAINT "permissions_assigned_by_user_id_fkey" FOREIGN KEY ("assigned_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "permissions" ADD CONSTRAINT "permissions_assigned_by_employee_id_fkey" FOREIGN KEY ("assigned_by_employee_id") REFERENCES "employees"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "wallets" ADD CONSTRAINT "wallets_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_wallet_id_fkey" FOREIGN KEY ("wallet_id") REFERENCES "wallets"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_api_entity_id_fkey" FOREIGN KEY ("api_entity_id") REFERENCES "api_entities"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_service_id_fkey" FOREIGN KEY ("service_id") REFERENCES "service_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_earnings" ADD CONSTRAINT "commission_earnings_transaction_id_fkey" FOREIGN KEY ("transaction_id") REFERENCES "transactions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_earnings" ADD CONSTRAINT "commission_earnings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_earnings" ADD CONSTRAINT "commission_earnings_from_user_id_fkey" FOREIGN KEY ("from_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "bank_details" ADD CONSTRAINT "bank_details_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ledger_entries" ADD CONSTRAINT "ledger_entries_service_id_fkey" FOREIGN KEY ("service_id") REFERENCES "service_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ledger_entries" ADD CONSTRAINT "ledger_entries_transaction_id_fkey" FOREIGN KEY ("transaction_id") REFERENCES "transactions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ledger_entries" ADD CONSTRAINT "ledger_entries_wallet_id_fkey" FOREIGN KEY ("wallet_id") REFERENCES "wallets"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_settings" ADD CONSTRAINT "commission_settings_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_settings" ADD CONSTRAINT "commission_settings_target_user_id_fkey" FOREIGN KEY ("target_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_settings" ADD CONSTRAINT "commission_settings_service_id_fkey" FOREIGN KEY ("service_id") REFERENCES "service_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_settings" ADD CONSTRAINT "commission_settings_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "commission_settings" ADD CONSTRAINT "commission_settings_created_by_employee_id_fkey" FOREIGN KEY ("created_by_employee_id") REFERENCES "employees"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "roles" ADD CONSTRAINT "roles_parent_id_fkey" FOREIGN KEY ("parent_id") REFERENCES "roles"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "roles" ADD CONSTRAINT "roles_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "departments" ADD CONSTRAINT "departments_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "service_providers" ADD CONSTRAINT "service_providers_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "api_integrations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "service_providers" ADD CONSTRAINT "service_providers_assigned_by_user_id_fkey" FOREIGN KEY ("assigned_by_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "service_providers" ADD CONSTRAINT "service_providers_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_integrations" ADD CONSTRAINT "api_integrations_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_kyc" ADD CONSTRAINT "user_kyc_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_kyc" ADD CONSTRAINT "user_kyc_address_id_fkey" FOREIGN KEY ("address_id") REFERENCES "addresses"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_kyc" ADD CONSTRAINT "user_kyc_business_kyc_id_fkey" FOREIGN KEY ("business_kyc_id") REFERENCES "business_kycs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_kyc" ADD CONSTRAINT "user_kyc_verified_by_user_id_fkey" FOREIGN KEY ("verified_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "business_kycs" ADD CONSTRAINT "business_kycs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "business_kycs" ADD CONSTRAINT "business_kycs_address_id_fkey" FOREIGN KEY ("address_id") REFERENCES "addresses"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "business_kycs" ADD CONSTRAINT "business_kycs_verified_by_user_id_fkey" FOREIGN KEY ("verified_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "business_kycs" ADD CONSTRAINT "business_kycs_verified_by_employee_id_fkey" FOREIGN KEY ("verified_by_employee_id") REFERENCES "employees"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cities" ADD CONSTRAINT "cities_state_id_fkey" FOREIGN KEY ("state_id") REFERENCES "states"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "addresses" ADD CONSTRAINT "addresses_city_id_fkey" FOREIGN KEY ("city_id") REFERENCES "cities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "addresses" ADD CONSTRAINT "addresses_state_id_fkey" FOREIGN KEY ("state_id") REFERENCES "states"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_entities" ADD CONSTRAINT "api_entities_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_entities" ADD CONSTRAINT "api_entities_service_id_fkey" FOREIGN KEY ("service_id") REFERENCES "service_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_webhooks" ADD CONSTRAINT "api_webhooks_api_entity_id_fkey" FOREIGN KEY ("api_entity_id") REFERENCES "api_entities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_webhooks" ADD CONSTRAINT "api_webhooks_transaction_id_fkey" FOREIGN KEY ("transaction_id") REFERENCES "transactions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ip_whitelists" ADD CONSTRAINT "ip_whitelists_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "system_settings" ADD CONSTRAINT "system_settings_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pii_consents" ADD CONSTRAINT "pii_consents_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pii_consents" ADD CONSTRAINT "pii_consents_user_kyc_id_fkey" FOREIGN KEY ("user_kyc_id") REFERENCES "user_kyc"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pii_consents" ADD CONSTRAINT "pii_consents_business_kyc_id_fkey" FOREIGN KEY ("business_kyc_id") REFERENCES "business_kycs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refunds" ADD CONSTRAINT "refunds_transaction_id_fkey" FOREIGN KEY ("transaction_id") REFERENCES "transactions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
