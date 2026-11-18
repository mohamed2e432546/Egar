import { readFileSync } from 'node:fs';
import {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
  RulesTestEnvironment,
} from '@firebase/rules-unit-testing';
import {
  doc,
  setDoc,
  getDoc,
  getDocs,
  updateDoc,
  deleteDoc,
  collection,
  query,
  where,
  serverTimestamp,
  writeBatch,
} from 'firebase/firestore';
import { describe, it, beforeAll, afterAll } from 'vitest';

let testEnv: RulesTestEnvironment;

const baseApartment = (ownerId = 'landlord_1', commissionRatePct = 10) => ({
  ownerId,
  ownerDisplayName: 'أحمد محمود',
  category: 'family_apartment',
  billingMode: 'monthly_only',
  dailyRateEgp: 0,
  monthlyRentEgp: 20000,
  studentBedsCount: 0,
  studentPricePerBedEgp: 0,
  title: 'شقة نيلية فاخرة في الزمالك',
  description: 'شقة مشمسة بإطلالة مباشرة على النيل وتشطيب معماري فاخر.',
  governorate: 'القاهرة',
  district: 'الزمالك',
  lat: 30.0609,
  lng: 31.2197,
  bedrooms: 3,
  bathrooms: 2,
  areaSqm: 185,
  furnishing: 'furnished',
  imageKey: 'zamalek_nile',
  verificationStatus: 'pending_review',
  availabilityStatus: 'available',
  commissionRatePct,
  mandateAccepted: true,
  createdAt: serverTimestamp(),
  updatedAt: serverTimestamp(),
});

const baseDossier = (ownerId = 'landlord_1', apartmentId = 'apt_1') => ({
  ownerId,
  apartmentId,
  nationalIdNumber: '29001010101234',
  ownerPhone: '01012345678',
  exactAddress: '14 شارع البرازيل، الدور الخامس، شقة 12',
  propertyRegistryNumber: 'SH-2024-8891',
  titleDeedFileName: 'contract_zamalek.pdf',
  titleDeedSha256: 'a'.repeat(64),
  utilityBillFileName: 'electricity_bill.pdf',
  utilityBillSha256: 'b'.repeat(64),
  ownerIbanOrInstapay: 'ahmed@instapay',
  digitalSignatureName: 'أحمد محمود حسن علي',
  exclusivityClauseAccepted: true,
  createdAt: serverTimestamp(),
});

describe('Ejar Hardened Firestore Rules — Dynamic Commission, Multi-Sector & Tenant KYC', () => {
  beforeAll(async () => {
    testEnv = await initializeTestEnvironment({
      projectId: 'demo-ejar-egypt',
      firestore: {
        rules: readFileSync('firestore.rules', 'utf8'),
      },
    });

    await testEnv.withSecurityRulesDisabled(async (ctx) => {
      const db = ctx.firestore();
      await setDoc(doc(db, 'apartments', 'apt_seed'), {
        ...baseApartment('landlord_1', 10),
        verificationStatus: 'verified',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      await setDoc(doc(db, 'apartments', 'apt_seed', 'legalDocs', 'dossier'), {
        ...baseDossier('landlord_1', 'apt_seed'),
        createdAt: new Date(),
      });
      await setDoc(doc(db, 'apartments', 'apt_rentable'), {
        ...baseApartment('landlord_1', 10),
        verificationStatus: 'verified',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      await setDoc(doc(db, 'bookings', 'bk_completed'), {
        apartmentId: 'apt_seed',
        apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
        category: 'family_apartment',
        governorate: 'القاهرة',
        tenantId: 'tenant_1',
        tenantDisplayName: 'سارة علي',
        landlordId: 'landlord_1',
        landlordDisplayName: 'أحمد محمود',
        rentalUnit: 'month',
        unitPriceEgp: 20000,
        unitsCount: 6,
        bedsBooked: 0,
        leaseMonths: 6,
        monthlyRentEgp: 20000,
        commissionRatePct: 10,
        totalRentEgp: 120000,
        platformCommissionEgp: 2000,
        landlordNetEgp: 118000,
        paymentMethod: 'instapay',
        paymentReference: 'IPAY-998877',
        status: 'completed',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });
  });

  afterAll(async () => {
    if (testEnv) await testEnv.cleanup();
  });

  it('1. Rejects identity spoofing on apartment creation', async () => {
    const attacker = testEnv.authenticatedContext('attacker_1', {
      email: 'attacker@example.com',
      email_verified: true,
    });
    const db = attacker.firestore();
    const batch = writeBatch(db);
    batch.set(doc(db, 'apartments', 'apt_spoof'), baseApartment('victim_uid'));
    batch.set(
      doc(db, 'apartments', 'apt_spoof', 'legalDocs', 'dossier'),
      baseDossier('victim_uid', 'apt_spoof')
    );
    await assertFails(batch.commit());
  });

  it('2. Rejects orphaned apartment creation without atomic legalDocs/dossier', async () => {
    const landlord = testEnv.authenticatedContext('landlord_1', {
      email: 'landlord@example.com',
      email_verified: true,
    });
    const db = landlord.firestore();
    await assertFails(setDoc(doc(db, 'apartments', 'apt_orphan'), baseApartment('landlord_1')));
  });

  it('3. Rejects self-verified apartment creation by non-admin', async () => {
    const landlord = testEnv.authenticatedContext('landlord_1', {
      email: 'landlord@example.com',
      email_verified: true,
    });
    const db = landlord.firestore();
    const batch = writeBatch(db);
    batch.set(doc(db, 'apartments', 'apt_selfver'), {
      ...baseApartment('landlord_1'),
      verificationStatus: 'verified',
    });
    batch.set(
      doc(db, 'apartments', 'apt_selfver', 'legalDocs', 'dossier'),
      baseDossier('landlord_1', 'apt_selfver')
    );
    await assertFails(batch.commit());
  });

  it('4. Rejects non-admin tampering with global /platformSettings/config', async () => {
    const attacker = testEnv.authenticatedContext('attacker_1', {
      email: 'attacker@example.com',
      email_verified: true,
    });
    const db = attacker.firestore();
    await assertFails(
      setDoc(doc(db, 'platformSettings', 'config'), {
        commissionRatePct: 1,
        commissionModel: 'one_time_brokerage',
        updatedByUid: 'attacker_1',
        updatedAt: serverTimestamp(),
      })
    );
  });

  it('5. Rejects shadow ghost field injection during update', async () => {
    const landlord = testEnv.authenticatedContext('landlord_1', {
      email: 'landlord@example.com',
      email_verified: true,
    });
    const db = landlord.firestore();
    await assertFails(
      updateDoc(doc(db, 'apartments', 'apt_seed'), {
        isFeaturedGhost: true,
        updatedAt: serverTimestamp(),
      })
    );
  });

  it('6. Rejects admin email spoofing when email_verified is false', async () => {
    const spoofAdmin = testEnv.authenticatedContext('spoof_admin', {
      email: '12mohamed01234@gmail.com',
      email_verified: false,
    });
    const db = spoofAdmin.firestore();
    await assertFails(getDoc(doc(db, 'apartments', 'apt_seed', 'legalDocs', 'dossier')));
  });

  it('7. Enforces Tenant KYC PII Split Isolation and blocks self-approval or stranger reads', async () => {
    const tenant = testEnv.authenticatedContext('tenant_kyc_1', {
      email: 'tenantkyc@example.com',
      email_verified: true,
    });
    const stranger = testEnv.authenticatedContext('stranger_1', {
      email: 'stranger@example.com',
      email_verified: true,
    });
    const admin = testEnv.authenticatedContext('admin_uid', {
      email: '12mohamed01234@gmail.com',
      email_verified: true,
    });

    const tenantDb = tenant.firestore();
    const strangerDb = stranger.firestore();
    const adminDb = admin.firestore();

    // Self-approved KYC fails
    const badBatch = writeBatch(tenantDb);
    badBatch.set(doc(tenantDb, 'tenantVerifications', 'tenant_kyc_1'), {
      userId: 'tenant_kyc_1',
      tenantDisplayName: 'كريم عادل',
      tenantCategory: 'student',
      verificationStatus: 'verified',
      reviewNote: '',
      submittedAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    badBatch.set(doc(tenantDb, 'tenantVerifications', 'tenant_kyc_1', 'privateDocs', 'kyc'), {
      userId: 'tenant_kyc_1',
      fullLegalName: 'كريم عادل محمد حسن',
      nationalIdNumber: '30305050101234',
      tenantPhone: '01099887766',
      occupationOrUniversity: 'جامعة القاهرة — كلية الهندسة',
      idCardFileName: 'national_id.pdf',
      idCardSha256: 'c'.repeat(64),
      supportingDocFileName: 'uni_card.pdf',
      supportingDocSha256: 'd'.repeat(64),
      updatedAt: serverTimestamp(),
    });
    await assertFails(badBatch.commit());

    // Valid pending_review KYC succeeds
    const goodBatch = writeBatch(tenantDb);
    goodBatch.set(doc(tenantDb, 'tenantVerifications', 'tenant_kyc_1'), {
      userId: 'tenant_kyc_1',
      tenantDisplayName: 'كريم عادل',
      tenantCategory: 'student',
      verificationStatus: 'pending_review',
      reviewNote: '',
      submittedAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    goodBatch.set(doc(tenantDb, 'tenantVerifications', 'tenant_kyc_1', 'privateDocs', 'kyc'), {
      userId: 'tenant_kyc_1',
      fullLegalName: 'كريم عادل محمد حسن',
      nationalIdNumber: '30305050101234',
      tenantPhone: '01099887766',
      occupationOrUniversity: 'جامعة القاهرة — كلية الهندسة',
      idCardFileName: 'national_id.pdf',
      idCardSha256: 'c'.repeat(64),
      supportingDocFileName: 'uni_card.pdf',
      supportingDocSha256: 'd'.repeat(64),
      updatedAt: serverTimestamp(),
    });
    await assertSucceeds(goodBatch.commit());

    // Stranger cannot read tenant private KYC
    await assertFails(
      getDoc(doc(strangerDb, 'tenantVerifications', 'tenant_kyc_1', 'privateDocs', 'kyc'))
    );

    // Verified Admin can inspect KYC and approve
    await assertSucceeds(
      getDoc(doc(adminDb, 'tenantVerifications', 'tenant_kyc_1', 'privateDocs', 'kyc'))
    );
    await assertSucceeds(
      updateDoc(doc(adminDb, 'tenantVerifications', 'tenant_kyc_1'), {
        verificationStatus: 'verified',
        reviewNote: 'تمت مراجعة البطاقة وكارنيه الجامعة بنجاح',
        updatedAt: serverTimestamp(),
      })
    );
  });

  it('8. Allows Admin to change global commission rate and enforces one-time brokerage commission on multi-month booking', async () => {
    const admin = testEnv.authenticatedContext('admin_uid', {
      email: '12mohamed01234@gmail.com',
      email_verified: true,
    });
    const tenant = testEnv.authenticatedContext('tenant_2', {
      email: 'tenant2@example.com',
      email_verified: true,
    });

    const adminDb = admin.firestore();
    const tenantDb = tenant.firestore();

    // Admin changes global commission rate to 8%
    await assertSucceeds(
      setDoc(doc(adminDb, 'platformSettings', 'config'), {
        commissionRatePct: 8,
        commissionModel: 'one_time_brokerage',
        updatedByUid: 'admin_uid',
        updatedAt: serverTimestamp(),
      })
    );

    // Tenant books apt_rentable (20,000/mo) for 6 months = 120,000 EGP total
    // One-time 8% commission on 1 month (20,000) = 1,600 EGP (NOT 9,600!)
    const rentalBatch = writeBatch(tenantDb);
    rentalBatch.set(doc(tenantDb, 'bookings', 'apt_rentable'), {
      apartmentId: 'apt_rentable',
      apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
      category: 'family_apartment',
      governorate: 'القاهرة',
      tenantId: 'tenant_2',
      tenantDisplayName: 'محمود جمال',
      landlordId: 'landlord_1',
      landlordDisplayName: 'أحمد محمود',
      rentalUnit: 'month',
      unitPriceEgp: 20000,
      unitsCount: 6,
      bedsBooked: 0,
      leaseMonths: 6,
      monthlyRentEgp: 20000,
      commissionRatePct: 8,
      totalRentEgp: 120000,
      platformCommissionEgp: 1600,
      landlordNetEgp: 118400,
      paymentMethod: 'instapay',
      paymentReference: 'IPAY-556677',
      status: 'escrow_paid',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    rentalBatch.delete(doc(tenantDb, 'apartments', 'apt_rentable'));
    await assertSucceeds(rentalBatch.commit());
  });

  it('9. Blocks self-approved rental requests and blocks cross-user notification spoofing', async () => {
    const attacker = testEnv.authenticatedContext('attacker_9', {
      email: 'attacker9@example.com',
      email_verified: true,
    });
    const db = attacker.firestore();

    // Cannot self-create rental request as 'approved'
    await assertFails(
      setDoc(doc(db, 'rentalRequests', 'req_self_approved'), {
        apartmentId: 'apt_seed',
        apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
        category: 'family_apartment',
        governorate: 'القاهرة',
        district: 'الزمالك',
        tenantId: 'attacker_9',
        tenantDisplayName: 'مهاجم',
        landlordId: 'landlord_1',
        landlordDisplayName: 'أحمد محمود',
        rentalUnit: 'month',
        unitPriceEgp: 20000,
        unitsCount: 3,
        bedsBooked: 0,
        commissionRatePct: 8,
        totalRentEgp: 60000,
        platformCommissionEgp: 1600,
        landlordNetEgp: 58400,
        status: 'approved',
        statusNote: 'محاولة تخطي الدفع',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );

    // Cannot spam unrelated victim_uid with fake notifications
    await assertFails(
      setDoc(doc(db, 'notifications', 'notif_spoof_1'), {
        recipientId: 'victim_uid',
        actorId: 'attacker_9',
        actorDisplayName: 'مهاجم',
        recipientRole: 'tenant',
        statusType: 'approved',
        relatedEntityType: 'rental_request',
        relatedEntityId: 'nonexistent_req',
        apartmentId: 'apt_seed',
        apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
        governorate: 'القاهرة',
        amountEgp: 60000,
        title: 'إشعار مزيف',
        message: 'محاولة إرسال إشعار مزيف لمستخدم آخر بدون طلب إيجار مشترك.',
        isRead: false,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );
  });

  it('10. Supports atomic rental request lifecycle notifications (pending_approval -> awaiting_payment -> cancelled) and read-only toggling', async () => {
    const tenant = testEnv.authenticatedContext('tenant_req_1', {
      email: 'tenantreq@example.com',
      email_verified: true,
    });
    const landlord = testEnv.authenticatedContext('landlord_1', {
      email: 'landlord1@example.com',
      email_verified: true,
    });
    const stranger = testEnv.authenticatedContext('stranger_99', {
      email: 'stranger99@example.com',
      email_verified: true,
    });

    const tenantDb = tenant.firestore();
    const landlordDb = landlord.firestore();
    const strangerDb = stranger.firestore();

    // 1. Tenant submits pending_approval request + notifications in atomic batch
    const submitBatch = writeBatch(tenantDb);
    submitBatch.set(doc(tenantDb, 'rentalRequests', 'req_valid_1'), {
      apartmentId: 'apt_seed',
      apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
      category: 'family_apartment',
      governorate: 'القاهرة',
      district: 'الزمالك',
      tenantId: 'tenant_req_1',
      tenantDisplayName: 'ياسمين فؤاد',
      landlordId: 'landlord_1',
      landlordDisplayName: 'أحمد محمود',
      rentalUnit: 'month',
      unitPriceEgp: 20000,
      unitsCount: 3,
      bedsBooked: 0,
      commissionRatePct: 8,
      totalRentEgp: 60000,
      platformCommissionEgp: 1600,
      landlordNetEgp: 58400,
      status: 'pending_approval',
      statusNote: 'بانتظار موافقة المالك لإتاحة السداد',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    submitBatch.set(doc(tenantDb, 'notifications', 'notif_landlord_1'), {
      recipientId: 'landlord_1',
      actorId: 'tenant_req_1',
      actorDisplayName: 'ياسمين فؤاد',
      recipientRole: 'landlord',
      statusType: 'pending_approval',
      relatedEntityType: 'rental_request',
      relatedEntityId: 'req_valid_1',
      apartmentId: 'apt_seed',
      apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
      governorate: 'القاهرة',
      amountEgp: 60000,
      title: 'طلب إيجار جديد بانتظار موافقتك',
      message: 'قدمت ياسمين فؤاد طلب إيجار لمدة 3 شهور وبانتظار موافقتك لفتح الدفع.',
      isRead: false,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    await assertSucceeds(submitBatch.commit());

    // Stranger cannot read landlord's notification
    await assertFails(getDoc(doc(strangerDb, 'notifications', 'notif_landlord_1')));

    // 2. Landlord approves request -> awaiting_payment + sends notification to tenant
    const approveBatch = writeBatch(landlordDb);
    approveBatch.update(doc(landlordDb, 'rentalRequests', 'req_valid_1'), {
      status: 'awaiting_payment',
      statusNote: 'تمت موافقة المالك — بانتظار إتمام الدفع عبر بوابة الضمان',
      updatedAt: serverTimestamp(),
    });
    approveBatch.set(doc(landlordDb, 'notifications', 'notif_tenant_approved_1'), {
      recipientId: 'tenant_req_1',
      actorId: 'landlord_1',
      actorDisplayName: 'أحمد محمود',
      recipientRole: 'tenant',
      statusType: 'awaiting_payment',
      relatedEntityType: 'rental_request',
      relatedEntityId: 'req_valid_1',
      apartmentId: 'apt_seed',
      apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
      governorate: 'القاهرة',
      amountEgp: 60000,
      title: 'تمت الموافقة على طلبك — بانتظار الدفع',
      message: 'وافق المالك على طلب الإيجار، يمكنك الآن سداد قيمة العقد عبر بوابة الضمان.',
      isRead: false,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    await assertSucceeds(approveBatch.commit());

    // Tenant marks notification as read (allowed), but cannot tamper with message text (denied)
    await assertFails(
      updateDoc(doc(tenantDb, 'notifications', 'notif_tenant_approved_1'), {
        isRead: true,
        message: 'نص معدل غير مصرح به',
        updatedAt: serverTimestamp(),
      })
    );
    await assertSucceeds(
      updateDoc(doc(tenantDb, 'notifications', 'notif_tenant_approved_1'), {
        isRead: true,
        updatedAt: serverTimestamp(),
      })
    );

    // 3. Tenant cancels request -> cancelled + logs cancellation notification
    const cancelBatch = writeBatch(tenantDb);
    cancelBatch.update(doc(tenantDb, 'rentalRequests', 'req_valid_1'), {
      status: 'cancelled',
      statusNote: 'تم إلغاء الطلب بناءً على رغبة المستأجر قبل الدفع',
      updatedAt: serverTimestamp(),
    });
    cancelBatch.set(doc(tenantDb, 'notifications', 'notif_tenant_cancel_1'), {
      recipientId: 'tenant_req_1',
      actorId: 'tenant_req_1',
      actorDisplayName: 'ياسمين فؤاد',
      recipientRole: 'tenant',
      statusType: 'cancelled',
      relatedEntityType: 'rental_request',
      relatedEntityId: 'req_valid_1',
      apartmentId: 'apt_seed',
      apartmentTitle: 'شقة نيلية فاخرة في الزمالك',
      governorate: 'القاهرة',
      amountEgp: 60000,
      title: 'تم إلغاء طلب الإيجار',
      message: 'تم إلغاء طلب الإيجار قبل السداد دون خصم أي رسوم.',
      isRead: false,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    await assertSucceeds(cancelBatch.commit());

    // Terminal state lock: cannot revert cancelled request back to awaiting_payment
    await assertFails(
      updateDoc(doc(tenantDb, 'rentalRequests', 'req_valid_1'), {
        status: 'awaiting_payment',
        statusNote: 'محاولة إعادة فتح طلب ملغي',
        updatedAt: serverTimestamp(),
      })
    );
  });

  it('11. Enforces Admin user bans across writes, blocks non-admin ban writes, and prevents Admin self-ban lockout', async () => {
    const admin = testEnv.authenticatedContext('admin_uid', {
      email: '12mohamed01234@gmail.com',
      email_verified: true,
    });
    const spammer = testEnv.authenticatedContext('spammer_uid_1', {
      email: 'spammer@example.com',
      email_verified: true,
    });

    const adminDb = admin.firestore();
    const spammerDb = spammer.firestore();

    // Non-admin cannot ban another user
    await assertFails(
      setDoc(doc(spammerDb, 'bannedUsers', 'victim_uid'), {
        userId: 'victim_uid',
        displayName: 'ضحية',
        reason: 'محاولة حظر غير مصرح بها',
        hideListings: true,
        bannedByUid: 'spammer_uid_1',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );

    // Admin cannot ban themselves (lockout protection)
    await assertFails(
      setDoc(doc(adminDb, 'bannedUsers', 'admin_uid'), {
        userId: 'admin_uid',
        displayName: 'مسؤول المنصة',
        reason: 'حظر بالخطأ',
        hideListings: true,
        bannedByUid: 'admin_uid',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );

    // Admin bans spammer_uid_1
    await assertSucceeds(
      setDoc(doc(adminDb, 'bannedUsers', 'spammer_uid_1'), {
        userId: 'spammer_uid_1',
        displayName: 'مستخدم مخالف',
        reason: 'نشر إعلانات وهمية وإزعاج المستخدمين',
        hideListings: true,
        bannedByUid: 'admin_uid',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );

    // Banned user cannot submit rental requests or favorites
    await assertFails(
      setDoc(doc(spammerDb, 'favorites', 'spammer_uid_1__apt_zamalek_nile_01'), {
        userId: 'spammer_uid_1',
        apartmentId: 'apt_zamalek_nile_01',
        title: 'شقة نيلية بانوراما في الزمالك',
        governorate: 'القاهرة',
        district: 'الزمالك',
        monthlyRentEgp: 32000,
        bedrooms: 3,
        bathrooms: 3,
        areaSqm: 210,
        furnishing: 'furnished',
        imageKey: 'zamalek_nile',
        ownerId: 'showcase_owner',
        ownerDisplayName: 'م. طارق المنشاوي',
        createdAt: serverTimestamp(),
      })
    );
  });

  it('12. Allows Admin to update full platformSettings (FX rates, discounts, master switches, removedShowcaseIds) and enforces pause switches', async () => {
    const admin = testEnv.authenticatedContext('admin_uid', {
      email: '12mohamed01234@gmail.com',
      email_verified: true,
    });
    const tenant = testEnv.authenticatedContext('tenant_active_12', {
      email: 'tenant12@example.com',
      email_verified: true,
    });

    const adminDb = admin.firestore();
    const tenantDb = tenant.firestore();

    await assertSucceeds(
      setDoc(doc(adminDb, 'platformSettings', 'config'), {
        commissionRatePct: 10,
        commissionModel: 'one_time_brokerage',
        escrowProtectionFeePct: 2,
        tenantDiscountPct: 5,
        usdRateEgp: 50.5,
        sarRateEgp: 13.45,
        eurRateEgp: 54.2,
        aedRateEgp: 13.75,
        announcementText: 'خصم 5% لفترة محدودة على رسوم الخدمة العقارية',
        allowNewListings: false,
        allowNewBookings: false,
        removedShowcaseIds: ['apt_dokki_studio_10'],
        updatedByUid: 'admin_uid',
        updatedAt: serverTimestamp(),
      })
    );

    // Non-admin booking/request is blocked while allowNewBookings == false
    await assertFails(
      setDoc(doc(tenantDb, 'rentalRequests', 'req_blocked_by_switch'), {
        apartmentId: 'apt_zamalek_nile_01',
        apartmentTitle: 'شقة نيلية بانوراما في الزمالك',
        category: 'family_apartment',
        governorate: 'القاهرة',
        district: 'الزمالك',
        tenantId: 'tenant_active_12',
        tenantDisplayName: 'سارة علي',
        landlordId: 'showcase_owner',
        landlordDisplayName: 'م. طارق المنشاوي',
        rentalUnit: 'month',
        unitPriceEgp: 32000,
        unitsCount: 2,
        bedsBooked: 0,
        commissionRatePct: 10,
        totalRentEgp: 64000,
        platformCommissionEgp: 3200,
        landlordNetEgp: 60800,
        status: 'awaiting_payment',
        statusNote: 'محاولة إرسال طلب أثناء إيقاف الحجوزات مؤقتاً',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );
  });

  it('13. Enforces per-category commission rates and whole_house building specifications', async () => {
    const admin = testEnv.authenticatedContext('admin_uid', {
      email: '12mohamed01234@gmail.com',
      email_verified: true,
    });
    const landlord = testEnv.authenticatedContext('landlord_house_1', {
      email: 'houseowner@example.com',
      email_verified: true,
    });

    const adminDb = admin.firestore();
    const landlordDb = landlord.firestore();

    await assertSucceeds(
      setDoc(doc(adminDb, 'platformSettings', 'config'), {
        commissionRatePct: 10,
        familyApartmentCommissionPct: 10,
        hotelRoomCommissionPct: 12,
        industrialFactoryCommissionPct: 8,
        studentHousingCommissionPct: 7,
        wholeHouseCommissionPct: 6,
        commissionModel: 'one_time_brokerage',
        allowNewListings: true,
        allowNewBookings: true,
        updatedByUid: 'admin_uid',
        updatedAt: serverTimestamp(),
      })
    );

    // Rejects whole_house listing using wrong commissionRatePct (10 instead of 6)
    const wrongRateBatch = writeBatch(landlordDb);
    wrongRateBatch.set(doc(landlordDb, 'apartments', 'hse_bad_rate'), {
      ...baseApartment('landlord_house_1', 10),
      category: 'whole_house',
      houseApartmentsCount: 4,
      houseFloorsCount: 3,
      houseHasGardenOrRoof: true,
      houseHasPrivateGarage: true,
      houseSpecsSummary: '4 شقق مستقلة العدادات + حديقة خاصة وجراج',
    });
    wrongRateBatch.set(
      doc(landlordDb, 'apartments', 'hse_bad_rate', 'legalDocs', 'dossier'),
      baseDossier('landlord_house_1', 'hse_bad_rate')
    );
    await assertFails(wrongRateBatch.commit());

    // Succeeds when whole_house listing uses active wholeHouseCommissionPct (6%) and valid apartment count
    const validHouseBatch = writeBatch(landlordDb);
    validHouseBatch.set(doc(landlordDb, 'apartments', 'hse_valid_1'), {
      ...baseApartment('landlord_house_1', 6),
      category: 'whole_house',
      monthlyRentEgp: 85000,
      houseApartmentsCount: 4,
      houseFloorsCount: 3,
      houseHasGardenOrRoof: true,
      houseHasPrivateGarage: true,
      houseSpecsSummary: 'منزل كامل مكون من 4 شقق وعدادات مستقلة وحديقة خاصة',
    });
    validHouseBatch.set(
      doc(landlordDb, 'apartments', 'hse_valid_1', 'legalDocs', 'dossier'),
      baseDossier('landlord_house_1', 'hse_valid_1')
    );
    await assertSucceeds(validHouseBatch.commit());
  });

  it('14. Enforces Admin-isolated, append-only immutable /adminActivityLogs/{logId}', async () => {
    const admin = testEnv.authenticatedContext('admin_uid', {
      email: '12mohamed01234@gmail.com',
      email_verified: true,
    });
    const stranger = testEnv.authenticatedContext('stranger_log_1', {
      email: 'stranger@example.com',
      email_verified: true,
    });

    const adminDb = admin.firestore();
    const strangerDb = stranger.firestore();

    // Non-admin cannot create or read activity logs
    await assertFails(
      setDoc(doc(strangerDb, 'adminActivityLogs', 'log_spoof_1'), {
        actionType: 'commission_change',
        severity: 'warning',
        targetType: 'platform_settings',
        targetId: 'config',
        targetLabel: 'نسب العمولة',
        summaryAr: 'محاولة تزوير سجل نشاط',
        summaryEn: 'Attempted forged activity log',
        previousValue: '10%',
        newValue: '1%',
        actorUid: 'stranger_log_1',
        actorDisplayName: 'مهاجم',
        createdAt: serverTimestamp(),
      })
    );

    // Verified Admin records an activity log entry
    await assertSucceeds(
      setDoc(doc(adminDb, 'adminActivityLogs', 'log_valid_1'), {
        actionType: 'commission_change',
        severity: 'warning',
        targetType: 'platform_settings',
        targetId: 'config',
        targetLabel: 'منزل كامل — نسبة العمولة',
        summaryAr: 'تحديث نسبة عمولة المنازل الكاملة إلى 6%',
        summaryEn: 'Updated Whole House commission rate to 6%',
        previousValue: '10%',
        newValue: '6%',
        actorUid: 'admin_uid',
        actorDisplayName: 'إدارة المنصة',
        createdAt: serverTimestamp(),
      })
    );

    // Stranger cannot read Admin activity logs
    await assertFails(getDoc(doc(strangerDb, 'adminActivityLogs', 'log_valid_1')));
    await assertFails(getDocs(collection(strangerDb, 'adminActivityLogs')));

    // Admin can read activity logs, but even Admin cannot mutate or delete past audit logs
    await assertSucceeds(getDoc(doc(adminDb, 'adminActivityLogs', 'log_valid_1')));
    await assertFails(
      updateDoc(doc(adminDb, 'adminActivityLogs', 'log_valid_1'), {
        newValue: '99%',
      })
    );
    await assertFails(deleteDoc(doc(adminDb, 'adminActivityLogs', 'log_valid_1')));
  });

  it('15. Enforces zero-PII /bookingDemandSignals/{bookingId} tied to completed bookings and blocks spoofed hotspots', async () => {
    const admin = testEnv.authenticatedContext('admin_uid', {
      email: '12mohamed01234@gmail.com',
      email_verified: true,
    });
    const landlord = testEnv.authenticatedContext('landlord_hm_1', {
      email: 'landlordhm@example.com',
      email_verified: true,
    });
    const tenant = testEnv.authenticatedContext('tenant_hm_1', {
      email: 'tenanthm@example.com',
      email_verified: true,
    });
    const unauth = testEnv.unauthenticatedContext();

    const adminDb = admin.firestore();
    const landlordDb = landlord.firestore();
    const tenantDb = tenant.firestore();
    const publicDb = unauth.firestore();

    // Attacker cannot forge a demand hotspot without a real completed booking
    await assertFails(
      setDoc(doc(tenantDb, 'bookingDemandSignals', 'fake_hotspot_1'), {
        bookingId: 'fake_hotspot_1',
        apartmentId: 'fake_hotspot_1',
        category: 'family_apartment',
        governorate: 'القاهرة',
        district: 'الزمالك',
        lat: 30.0642,
        lng: 31.2179,
        unitsCount: 6,
        totalRentEgp: 192000,
        status: 'completed',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );

    // Seed verified listing, book via escrow, then atomically complete + emit demand signal
    const listBatch = writeBatch(landlordDb);
    listBatch.set(doc(landlordDb, 'apartments', 'apt_hm_valid_1'), baseApartment('landlord_hm_1', 10));
    listBatch.set(
      doc(landlordDb, 'apartments', 'apt_hm_valid_1', 'legalDocs', 'dossier'),
      baseDossier('landlord_hm_1', 'apt_hm_valid_1')
    );
    await assertSucceeds(listBatch.commit());
    await assertSucceeds(
      updateDoc(doc(adminDb, 'apartments', 'apt_hm_valid_1'), {
        verificationStatus: 'verified',
        updatedAt: serverTimestamp(),
      })
    );

    const bookBatch = writeBatch(tenantDb);
    bookBatch.set(doc(tenantDb, 'bookings', 'apt_hm_valid_1'), {
      apartmentId: 'apt_hm_valid_1',
      apartmentTitle: 'شقة نيلية موثقة في الزمالك',
      category: 'family_apartment',
      governorate: 'القاهرة',
      district: 'الزمالك',
      lat: 30.0642,
      lng: 31.2179,
      tenantId: 'tenant_hm_1',
      tenantDisplayName: 'مروان خالد',
      landlordId: 'landlord_hm_1',
      rentalUnit: 'month',
      unitPriceEgp: 20000,
      unitsCount: 3,
      bedsBooked: 0,
      leaseMonths: 3,
      monthlyRentEgp: 20000,
      commissionRatePct: 10,
      totalRentEgp: 60000,
      platformCommissionEgp: 2000,
      landlordNetEgp: 58000,
      paymentMethod: 'instapay',
      paymentReference: 'IPAY_HM_001',
      status: 'escrow_paid',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    bookBatch.delete(doc(tenantDb, 'apartments', 'apt_hm_valid_1'));
    await assertSucceeds(bookBatch.commit());

    // Cannot create demand signal while booking is still escrow_paid (not completed)
    await assertFails(
      setDoc(doc(tenantDb, 'bookingDemandSignals', 'apt_hm_valid_1'), {
        bookingId: 'apt_hm_valid_1',
        apartmentId: 'apt_hm_valid_1',
        category: 'family_apartment',
        governorate: 'القاهرة',
        district: 'الزمالك',
        lat: 30.0642,
        lng: 31.2179,
        unitsCount: 3,
        totalRentEgp: 60000,
        status: 'completed',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
    );

    // Atomic handover completion + zero-PII demand signal emission succeeds
    const completeBatch = writeBatch(tenantDb);
    completeBatch.update(doc(tenantDb, 'bookings', 'apt_hm_valid_1'), {
      status: 'completed',
      updatedAt: serverTimestamp(),
    });
    completeBatch.set(doc(tenantDb, 'bookingDemandSignals', 'apt_hm_valid_1'), {
      bookingId: 'apt_hm_valid_1',
      apartmentId: 'apt_hm_valid_1',
      category: 'family_apartment',
      governorate: 'القاهرة',
      district: 'الزمالك',
      lat: 30.0642,
      lng: 31.2179,
      unitsCount: 3,
      totalRentEgp: 60000,
      status: 'completed',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    await assertSucceeds(completeBatch.commit());

    // Public unauthenticated visitors can query completed demand signals for the Heatmap
    await assertSucceeds(
      getDocs(query(collection(publicDb, 'bookingDemandSignals'), where('status', '==', 'completed')))
    );
  });
});



