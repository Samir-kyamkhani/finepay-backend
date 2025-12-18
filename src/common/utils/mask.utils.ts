import { Injectable } from '@nestjs/common';

@Injectable()
export class MaskService {
  maskPII(value: string, type: string): string {
    if (!value || value.trim() === '') {
      return '•••••';
    }

    const cleanValue = value.trim().toUpperCase();

    // Simple masking for all types
    switch (type) {
      case 'PAN':
        return `${cleanValue.substring(0, 2)}•••••${cleanValue.substring(cleanValue.length - 2)}`;
      case 'GST':
        return `${cleanValue.substring(0, 2)}•••••${cleanValue.substring(cleanValue.length - 3)}`;
      case 'UDHYAM':
        return `UDHYAM-•••••`;
      default:
        return `•••••`;
    }
  }
}
