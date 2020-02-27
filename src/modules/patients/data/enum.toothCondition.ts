// possible conditions of a tooth
export const ToothCondition = {
  sound: "sound",
  filled: "filled",
  compromised: "compromised",
  endo: "endo",
  missing: "missing",
  rotated: "rotated",
  displaced: "displaced",
  "gum-recessed": "gum-recessed"
};

export const Diagnosis: { [key: string]: any } = {
  K00: {
    title: "K00 Disorders of tooth development and eruption",
    diagnosis: [
      {
        id: "K00.0",
        value: "Anodontia"
      },
      {
        id: "K00.1",
        value: "Supernumerary teeth"
      },
      {
        id: "K00.2",
        value: "Abnormalities of tooth size and form"
      },
      {
        id: "K00.3",
        value: "Mottled Teeth"
      },
      {
        id: "K00.4",
        value: "Disturbances in tooth formation"
      },
      {
        id: "K00.5",
        value:
          "Hereditary disturbances in tooth structure, not elsewhere classified"
      },
      {
        id: "K00.6",
        value: "Disturbances in tooth eruption"
      },
      {
        id: "K00.7",
        value: "Teething Syndrome"
      },
      {
        id: "K00.8",
        value: "Other disorders of tooth development"
      },
      {
        id: "K00.9",
        value: "Disorders of tooth development, unspecified"
      }
    ]
  },
  K01: {
    title: "K01 Embedded and impacted teeth",
    diagnosis: [
      {
        id: "K01.0",
        value: "Embedded Teeth"
      },
      {
        id: "K01.1",
        value: "Impacted Teeth"
      }
    ]
  },
  K02: {
    title: "K02 Dental Caries",
    diagnosis: [
      {
        id: "K02.0",
        value: "Caries limited to enamel"
      },
      {
        id: "K02.1",
        value: "Caries of dentine"
      },
      {
        id: "K02.2",
        value: "Caries of cementum"
      },
      {
        id: "K02.3",
        value: "Arrested dental caries"
      },
      {
        id: "K02.4",
        value: "Odontoclasia"
      },
      {
        id: "K02.5",
        value: "Other dental caries"
      },
      {
        id: "K02.6",
        value: "Dental caries, unspecified"
      }
    ]
  },
  K03: {
    title: "K03 Other diseases of hard tissues of teeth",
    diagnosis: [
      {
        id: "K03.0",
        value: "Excessive attrition of teeth"
      },
      {
        id: "K03.1",
        value: "Abrasion of teeth"
      },
      {
        id: "K03.2",
        value: "Erosion of teeth"
      },
      {
        id: "K03.3",
        value: "Pathological resorption of teeth"
      },
      {
        id: "K03.4",
        value: "Hypercementosis"
      },
      {
        id: "K03.5",
        value: "Ankylosis of teeth"
      },
      {
        id: "K03.6",
        value: "Deposits [accretions] on teeth"
      },
      {
        id: "K03.7",
        value: "Posteruptive colour change of dental hard tissues"
      },
      {
        id: "K03.8",
        value: "Other specified diseases of hard tissue of teeth"
      },
      {
        id: "K03.9",
        value: "Diseases of hard tissue or teeth, unspecified"
      }
    ]
  },
  K04: {
    title: "K04 Diseases of the pulp an periapical tissues",
    diagnosis: [
      {
        id: "K04.0",
        value: "0 Pulpitis"
      },
      {
        id: "K04.1",
        value: "Necrosis of pulp"
      },
      {
        id: "K04.2",
        value: "Pulp degeneration"
      },
      {
        id: "K04.3",
        value: "Abnormal hard tissue formation in pulp"
      },
      {
        id: "K04.4",
        value: "Acute apical periodontitis of pulpal origin"
      },
      {
        id: "K04.5",
        value: "Chronic apical periodontitis"
      },
      {
        id: "K04.6",
        value:
          "Periapical abscess with sinusRoot canal treatment,endodontic,obturate,abcess"
      },
      {
        id: "K04.7",
        value: "Periapical abscess without sinus"
      },
      {
        id: "K04.8",
        value: "Radicular cyst"
      },
      {
        id: "K04.9",
        value:
          "Other and unspecified diseases of the pulp and periapical tissues"
      }
    ]
  },
  K05: {
    title: "K05 Gingivitis and periodontal diseases",
    diagnosis: [
      {
        if: "K05.0",
        value: ""
      },
      {
        if: "K05.1",
        value: "Chronic gingivitis"
      },
      {
        if: "K05.2",
        value: "Acute Periodontitis"
      },
      {
        if: "K05.3",
        value: "Chronic Periodontitis"
      },
      {
        if: "K05.4",
        value: "Periodontosis"
      },
      {
        if: "K05.5",
        value: "Other periodontal disease"
      },
      {
        if: "K05.6",
        value: "Periodontal disease, unspecified"
      }
    ]
  },
  K06: {
    title: "K06 Other disorders of the gingiva and edentulous alveolar ridges",
    diagnosis: [
      {
        id: "K06.0",
        value: "Gingival recession"
      },
      {
        id: "K06.1",
        value: "Gingival enlargement"
      },
      {
        id: "K06.2",
        value:
          "Gingiva and edentulous alveolar ridge lesions associated with trauma"
      },
      {
        id: "K06.3",
        value:
          "Other specified disorders of the gingiva and edentulous alveolar ridge"
      },
      {
        id: "K06.4",
        value:
          "Disorder of the gingiva and edentulous alveolar ridge, unspecified"
      }
    ]
  },
  K07: {
    title: "K07 Dento-facial anomalies including malocclusion",
    diagnosis: [
      {
        id: "K07.0",
        value: "Major anomalies of jaw size"
      },
      {
        id: "K07.1",
        value: "Anomalies of jaw-cranial base relationship"
      },
      {
        id: "K07.2",
        value: "Anomaliies of dental arch relationship"
      },
      {
        id: "K07.3",
        value: "Anomalies of tooth position"
      },
      {
        id: "K07.4",
        value: "Malocclusion, unspecified"
      },
      {
        id: "K07.5",
        value: "Dento-facial functional abnormalities"
      },
      {
        id: "K07.6",
        value: "Temporo-mandibular joint disorders"
      },
      {
        id: "K07.7",
        value: "Other dento-facial anomalies"
      },
      {
        id: "K07.8",
        value: "Dento-facial anomaly, Unspecified"
      }
    ]
  },
  K08: {
    title: "K08 Other disorders of the teeth and supporting structures",
    diagnosis: [
      {
        id: "K08.0",
        value: "Exfoliation of teeth due to systemic disorders"
      },
      {
        id: "K08.1",
        value:
          "Loss of teeth due to extraction, accident or local periodontal disease"
      },
      {
        id: "K08.2",
        value: "Atrophy of edentulous alveolar ridge"
      },
      {
        id: "K08.3",
        value: "Retained dental root"
      },
      {
        id: "K08.4",
        value: "Other specified disorders of teeth and supporting structures"
      },
      {
        id: "K08.5",
        value: "Disorders of teeth and supporting structures, unspecified"
      }
    ]
  },
  K09: {
    title: "K09 Cysts of oral origin, not elsewhere classified",
    diagnosis: [
      {
        id: "K09.0",
        value: "Developmental odontogenic cysts"
      },
      {
        id: "K09.1",
        value: "Developmental (non-odontogenic) cysts of oral region"
      },
      {
        id: "K09.2",
        value: "Other cysts of jaws"
      },
      {
        id: "K09.3",
        value: "Other cysts of oral region, not elsewhere classified"
      },
      {
        id: "K09.4",
        value: "Cysts of oral region, unspecified"
      }
    ]
  },
  K10: {
    title: "K10 Other diseases of jaws",
    diagnosis: [
      {
        id: "K10.0",
        value: "Developmental disorders of jaws"
      },
      {
        id: "K10.1",
        value: "Giant cell granuloma, central"
      },
      {
        id: "K10.2",
        value: "Inflammatory conditions of jaws"
      },
      {
        id: "K10.3",
        value: "Inflammatory conditions of jaws"
      },
      {
        id: "K10.4",
        value: "Other specified diseases of jaws"
      },
      {
        id: "K10.5",
        value: "Disease of jaws, unspecified"
      }
    ]
  },
  K11: {
    title: "K11 Diseases of the salivary glands",
    diagnosis: [
      {
        id: "K11.0",
        value: "Atrophy of salivary gland"
      },
      {
        id: "K11.1",
        value: "Hypertrophy of salivary gland"
      },
      {
        id: "K11.2",
        value: "Sialoadenitis"
      },
      {
        id: "K11.3",
        value: "Abscess of salivary gland"
      },
      {
        id: "K11.4",
        value: "Fistula of salivary gland"
      },
      {
        id: "K11.5",
        value: "5 Sialolithiasis"
      },
      {
        id: "K11.6",
        value: "Mucocoele of salivary gland"
      },
      {
        id: "K11.7",
        value: "Disturbances of salivary secretion"
      },
      {
        id: "K11.8",
        value: "Other diseases of salivary glands"
      },
      {
        id: "K11.9",
        value: "Disease of salivary gland, unspecified"
      }
    ]
  },
  K12: {
    title: "K12 Stomatitis and related lesions",
    diagnosis: [
      {
        id: "K12.0",
        value: "Recurrent oral aphthae"
      },
      {
        id: "K12.1",
        value: "Other forms of stomatitis"
      },
      {
        id: "K12.2",
        value: "Cellulitis and abscess of mouth. Excludes K04.6-K04.7 and K02.5"
      }
    ]
  },
  K13: {
    title: "K13 Other diseases of the lip and oral mucosa",
    diagnosis: [
      {
        id: "K13.0",
        value: "Diseases of lips"
      },
      {
        id: "K13.1",
        value: "Cheek and lip biting"
      },
      {
        id: "K13.2",
        value:
          "Leukoplakia and other disturbances of the oral epithelium including tongue"
      },
      {
        id: "K13.3",
        value: "Hairy Leukoplakia"
      },
      {
        id: "K13.4",
        value: "Granuloma and granuloma-like lesions of oral mucosa"
      },
      {
        id: "K13.5",
        value: "Oral submucous fibrosis"
      },
      {
        id: "K13.6",
        value: "Irritative hyperplasia of oral mucosa"
      },
      {
        id: "K13.7",
        value: "Other and unspecified lesions of oral mucosa"
      }
    ]
  },
  K14: {
    title: "K14 Diseases of the tongue",
    diagnosis: [
      {
        id: "K14.0",
        value: "GlossitisUlcer, abscess"
      },
      {
        id: "K14.1",
        value: "Geographic Tongue"
      },
      {
        id: "K14.2",
        value: "Median Rhomboid Glossitis"
      },
      {
        id: "K14.3",
        value: "Hypertrophy of papillaeBlack hairy tongue"
      },
      {
        id: "K14.4",
        value: "Atrophy of papillae"
      },
      {
        id: "K14.5",
        value: "Plicated tongueScrotal, fissured tongue"
      },
      {
        id: "K14.6",
        value: "Glossodynia"
      },
      {
        id: "K14.7",
        value: "Other diseases of the tongue"
      },
      {
        id: "K14.8",
        value: "Disease of the tongue, unspecified"
      }
    ]
  },
  ZZCodes: {
    title: "Z Z codes",
    diagnosis: [
      {
        id: "Z01.2",
        value: "Dental examination"
      },
      {
        id: "Z41.8",
        value: "Other procedures for purposes other than remedying health state"
      },
      {
        id: "Z29.8",
        value: "Other specified prophylactic procedures"
      },
      {
        id: "Z46.3",
        value: "Fitting and adjusting of dental prosthetic device"
      },
      {
        id: "Z46.4",
        value: "Fitting and adjusting of dental orthodontic device"
      },
      {
        id: "Attention to surgical dressings or sutures",
        value: "Z48.0"
      },
      {
        id: "Z45.8",
        value: "Adjustment and management of other implanted devices"
      },
      {
        id: "Z53.2",
        value:
          "Procedure not carried out because of patient's decision for other and unspecified reasons"
      }
    ]
  }
};

export const procedures = [
  {
    id: "diagnosis",
    title: "Diagnosis"
  },
  {
    id: "restoration",
    title: "Restoration",
    children: ["Medial", "Oclusial", "Distal", "Lingual", "Buccal"]
  },
  {
    id: "rootCanal",
    title: "Root Canal",
    children: ["Post and Core"]
  },
  {
    id: "hygiene",
    title: "Hygiene"
  },
  {
    id: "whitening",
    title: "Whitening"
  },
  {
    id: "prosthetics",
    title: "Prosthetics",
    children: ["Bridge"]
  },
  {
    id: "implantation",
    title: "Implantation"
  },
  {
    id: "orthodontics",
    title: "Orthodontics"
  },
  {
    id: "surgery",
    title: "Surgery"
  }
];

export const procedureList = [
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 6,
    value: "ConeBeam CT X-ray (1 jaw)",
    defaultPrice: 30
  },
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 5,
    value: "Cephalometric X-ray",
    defaultPrice: 15
  },
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 1,
    value: "Consultation and treatment plan",
    defaultPrice: 0
  },
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 7,
    value: "ConeBeam CT X-ray (2 jaw)",
    defaultPrice: 40
  },
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 4,
    value: "Panoramic X-Ray",
    defaultPrice: 15
  },
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 2,
    value: "Periapical X-Ray",
    defaultPrice: 0
  },
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 8,
    value: "Blood test",
    defaultPrice: 25
  },
  {
    parentId: "diagnosis",
    parentIndex: 1,
    order: 3,
    value: "Bitewing X-Ray",
    defaultPrice: 0
  },

  //2 restoration
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 7,
    value: "Sealant",
    defaultPrice: 15
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 4,
    value: "Composite filling (extensive)",
    defaultPrice: 50
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 6,
    value: "Tooth gap filling",
    defaultPrice: 50
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 8,
    value: "Composite veneer	",
    defaultPrice: 100
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 3,
    value: "Composite filling (enlarged)",
    defaultPrice: 40
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 5,
    value: "Cosmetic Composite resin restoration",
    defaultPrice: 40
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 2,
    value: "Composite filling (moderate)",
    defaultPrice: 30
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 9,
    value: "Dental dam",
    defaultPrice: 15
  },
  {
    parentId: "restoration",
    parentIndex: 2,
    order: 1,
    value: "Composite filling (minimal)",
    defaultPrice: 15
  },

  //3 Root canal
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 1,
    value: "Root canal treatment (anterior)",
    defaultPrice: 100
  },
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 3,
    value: "Root canal treatment (molar)",
    defaultPrice: 200
  },
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 4,
    value: "Root canal re-treatment (anterior)",
    defaultPrice: 150
  },
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 5,
    value: "Root canal re-treatment (premolar)",
    defaultPrice: 200
  },
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 2,
    value: "Root canal treatment (premolar)",
    defaultPrice: 150
  },
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 8,
    value: "Abscess drainage/Abscess treatment",
    defaultPrice: 50
  },
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 7,
    value: "Direct pulp capping",
    defaultPrice: 50
  },
  {
    parentId: "rootCanal",
    parentIndex: 3,
    order: 6,
    value: "Root canal re-treatment (molar)",
    defaultPrice: 250
  },

  //4 Hygiene
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 3,
    value: "Cleaning and polishing (Heavy calculus)	",
    defaultPrice: 25
  },
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 4,
    value: "Teeth cleaning and polishing under local anesthetics",
    defaultPrice: 100
  },
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 5,
    value: "Periodontal pocket treatment (non-surgical)",
    defaultPrice: 10
  },
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 7,
    value: "Gum contouring surgery",
    defaultPrice: 100
  },
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 1,
    value: "Cleaning and polishing (Mild calculus)",
    defaultPrice: 15
  },
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 2,
    value: "Cleaning and polishing (Moderate calculus)	",
    defaultPrice: 20
  },
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 8,
    value: "Gum grafting",
    defaultPrice: 300
  },
  {
    parentId: "hygiene",
    parentIndex: 4,
    order: 6,
    value: "Operculectomy",
    defaultPrice: 25
  },

  //5 Whitening
  {
    parentId: "whitening",
    parentIndex: 5,
    order: 1,
    value: "At-home whitening kit (Zoom)",
    defaultPrice: 100
  },
  {
    parentId: "whitening",
    parentIndex: 5,
    order: 4,
    value: "Internal bleaching",
    defaultPrice: 100
  },
  {
    parentId: "whitening",
    parentIndex: 5,
    order: 2,
    value: "In-office laser whitening with Zoom 2",
    defaultPrice: 250
  },
  {
    parentId: "whitening",
    parentIndex: 5,
    order: 3,
    value: "Whitening Combination Package",
    defaultPrice: 280
  },

  //6 Prosthetics
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 9,
    value: "Porcleain fused to titanium crown (CAD/CAM)",
    defaultPrice: 350
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 8,
    value: "All-porcelain overlay (Emax CAD)",
    defaultPrice: 400
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 4,
    value: "Composite inlay",
    defaultPrice: 100
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 5,
    value: "All-porcelain inlay (Emax CAD)",
    defaultPrice: 200
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 1,
    value: "Crown removal",
    defaultPrice: 15
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 3,
    value: "Re-cement crown",
    defaultPrice: 25
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 2,
    value: "Temporary crown (PMMA)	",
    defaultPrice: 20
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 6,
    value: "Composite onlay",
    defaultPrice: 100
  },
  {
    parentId: "prosthetics",
    parentIndex: 6,
    order: 7,
    value: "All-porcelain onlay (Emax CAD)",
    defaultPrice: 350
  },

  //7 Implantation
  {
    parentId: "implantation",
    parentIndex: 7,
    order: 6,
    value: "All on 8 (Nobel Biocare/SGS Switzerland dental implant)",
    defaultPrice: 13000
  },
  {
    parentId: "implantation",
    parentIndex: 7,
    order: 3,
    value: "Guided bone regeneration membrane",
    defaultPrice: 400
  },
  {
    parentId: "implantation",
    parentIndex: 7,
    order: 4,
    value: "Sinus augmentation (Closed)",
    defaultPrice: 300
  },
  {
    parentId: "implantation",
    parentIndex: 7,
    order: 7,
    value: "All on 6 (Nobel Biocare/SGS Switzerland dental implant)",
    defaultPrice: 10000
  },
  {
    parentId: "implantation",
    parentIndex: 7,
    order: 5,
    value: "Sinus augmentation (Open)",
    defaultPrice: 600
  },
  {
    parentId: "implantation",
    parentIndex: 7,
    order: 2,
    value: "Bone grafting",
    defaultPrice: 600
  },
  {
    parentId: "implantation",
    parentIndex: 7,
    order: 1,
    value: "Nobel Biocare/SGS Switzerland dental implant",
    defaultPrice: 1500
  },

  //8 Orthodontics
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 9,
    value: "Functional appliance",
    defaultPrice: 300
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 2,
    value:
      "Traditional metal braces - Requires extraction (fee for extraction is not included)",
    defaultPrice: 1750
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 5,
    value:
      "Traditional ceramic braces - Requires extraction (fee for extraction is not included",
    defaultPrice: 2590
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 4,
    value: "Traditional ceramic braces - Simple case: no extraction required	",
    defaultPrice: 2000
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 3,
    value:
      "Traditional metal braces - Complicated case: lost of molar, root treated teeth etc",
    defaultPrice: 2500
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 7,
    value: "Invisalign ClinCheck	",
    defaultPrice: 250
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 8,
    value: "Invisalign",
    defaultPrice: 4500
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 1,
    value: "Traditional metal braces - Simple case: no extraction required",
    defaultPrice: 1500
  },
  {
    parentId: "orthodontics",
    parentIndex: 8,
    order: 6,
    value:
      "Traditional ceramic braces - Complicated case: lost of molar, root treated teeth etc",
    defaultPrice: 2800
  },

  //9 Surgery
  {
    parentId: "surgery",
    parentIndex: 9,
    order: 1,
    value: "Permanent tooth extraction	",
    defaultPrice: 80
  },
  {
    parentId: "surgery",
    parentIndex: 9,
    order: 3,
    value: "Wisdom tooth extraction (lower jaw)	",
    defaultPrice: 125
  },
  {
    parentId: "surgery",
    parentIndex: 9,
    order: 5,
    value: "Tooth extraction with bone grafting	",
    defaultPrice: 500
  },
  {
    parentId: "surgery",
    parentIndex: 9,
    order: 6,
    value: "Crown lengthening surgery",
    defaultPrice: 100
  },
  {
    parentId: "surgery",
    parentIndex: 9,
    order: 7,
    value: "Gum contouring surgery	",
    defaultPrice: 150
  },
  {
    parentId: "surgery",
    parentIndex: 9,
    order: 4,
    value: "Surgical tooth extraction	",
    defaultPrice: 175
  },
  {
    parentId: "surgery",
    parentIndex: 9,
    order: 2,
    value: "Wisdom tooth extraction (upper jaw)",
    defaultPrice: 100
  }
];

export function conditionToColor(c: keyof typeof ToothCondition) {
  if (c === "compromised") {
    return "#FFCDD2";
  } else if (c === "endo") {
    return "#D1C4E9";
  } else if (c === "filled") {
    return "#FFE082";
  } else if (c === "missing") {
    return "#BDBDBD";
  } else if (c === "rotated") {
    return "#B2EBF2";
  } else if (c === "gum-recessed") {
    return "#F48FB1";
  } else if (c === "displaced") {
    return "#b2dfdb";
  } else {
    return "#FAFAFA";
  }
}
