# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'E:/k/k_pyside/fproject/k_frist4.ui'
#
# Created: Wed May 31 12:02:53 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

class Ui_k_widget(object):
    def setupUi(self, k_widget):
        k_widget.setObjectName("k_widget")
        k_widget.setEnabled(True)
        k_widget.resize(800, 794)
        k_widget.setMinimumSize(QtCore.QSize(0, 0))
        k_widget.setSizeIncrement(QtCore.QSize(0, 0))
        self.k_wlayout = QtGui.QVBoxLayout(k_widget)
        self.k_wlayout.setObjectName("k_wlayout")
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.label = QtGui.QLabel(k_widget)
        self.label.setObjectName("label")
        self.horizontalLayout_4.addWidget(self.label)
        self.comboBox_2 = QtGui.QComboBox(k_widget)
        self.comboBox_2.setMinimumSize(QtCore.QSize(70, 20))
        self.comboBox_2.setMaximumSize(QtCore.QSize(60, 16777215))
        self.comboBox_2.setObjectName("comboBox_2")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.horizontalLayout_4.addWidget(self.comboBox_2)
        spacerItem = QtGui.QSpacerItem(10200, 20, QtGui.QSizePolicy.Maximum, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.k_wlayout.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_5 = QtGui.QHBoxLayout()
        self.horizontalLayout_5.setSizeConstraint(QtGui.QLayout.SetDefaultConstraint)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.label_2 = QtGui.QLabel(k_widget)
        self.label_2.setMinimumSize(QtCore.QSize(0, 0))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_5.addWidget(self.label_2)
        self.lineEdit = QtGui.QLineEdit(k_widget)
        self.lineEdit.setMinimumSize(QtCore.QSize(0, 30))
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout_5.addWidget(self.lineEdit)
        spacerItem1 = QtGui.QSpacerItem(20, 0, QtGui.QSizePolicy.Maximum, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem1)
        self.pushButton_2 = QtGui.QPushButton(k_widget)
        self.pushButton_2.setMinimumSize(QtCore.QSize(90, 30))
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_5.addWidget(self.pushButton_2)
        self.k_wlayout.addLayout(self.horizontalLayout_5)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.spinBox = QtGui.QSpinBox(k_widget)
        self.spinBox.setObjectName("spinBox")
        self.horizontalLayout.addWidget(self.spinBox)
        self.k_label1 = QtGui.QLabel(k_widget)
        self.k_label1.setEnabled(True)
        self.k_label1.setTextFormat(QtCore.Qt.AutoText)
        self.k_label1.setScaledContents(False)
        self.k_label1.setObjectName("k_label1")
        self.horizontalLayout.addWidget(self.k_label1)
        self.comboBox = QtGui.QComboBox(k_widget)
        self.comboBox.setObjectName("comboBox")
        self.horizontalLayout.addWidget(self.comboBox)
        self.horizontalSlider = QtGui.QSlider(k_widget)
        self.horizontalSlider.setOrientation(QtCore.Qt.Horizontal)
        self.horizontalSlider.setObjectName("horizontalSlider")
        self.horizontalLayout.addWidget(self.horizontalSlider)
        self.pushButton = QtGui.QPushButton(k_widget)
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout.addWidget(self.pushButton)
        self.verticalScrollBar = QtGui.QScrollBar(k_widget)
        self.verticalScrollBar.setOrientation(QtCore.Qt.Vertical)
        self.verticalScrollBar.setObjectName("verticalScrollBar")
        self.horizontalLayout.addWidget(self.verticalScrollBar)
        self.k_wlayout.addLayout(self.horizontalLayout)
        self.k_button2 = QtGui.QPushButton(k_widget)
        self.k_button2.setMinimumSize(QtCore.QSize(0, 50))
        self.k_button2.setMaximumSize(QtCore.QSize(16777215, 50))
        self.k_button2.setObjectName("k_button2")
        self.k_wlayout.addWidget(self.k_button2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.k_treeView = QtGui.QTreeView(k_widget)
        self.k_treeView.setMaximumSize(QtCore.QSize(450, 16777215))
        self.k_treeView.setObjectName("k_treeView")
        self.horizontalLayout_3.addWidget(self.k_treeView)
        self.k_tabWidget = QtGui.QTableWidget(k_widget)
        self.k_tabWidget.setMinimumSize(QtCore.QSize(580, 0))
        self.k_tabWidget.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.k_tabWidget.setObjectName("k_tabWidget")
        self.k_tabWidget.setColumnCount(3)
        self.k_tabWidget.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.k_tabWidget.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.k_tabWidget.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.k_tabWidget.setHorizontalHeaderItem(2, item)
        self.horizontalLayout_3.addWidget(self.k_tabWidget)
        self.k_wlayout.addLayout(self.horizontalLayout_3)
        self.k_progressBar = QtGui.QProgressBar(k_widget)
        self.k_progressBar.setProperty("value", 24)
        self.k_progressBar.setObjectName("k_progressBar")
        self.k_wlayout.addWidget(self.k_progressBar)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.k_Bopen = QtGui.QPushButton(k_widget)
        self.k_Bopen.setMinimumSize(QtCore.QSize(0, 30))
        self.k_Bopen.setMaximumSize(QtCore.QSize(150, 30))
        self.k_Bopen.setDefault(False)
        self.k_Bopen.setObjectName("k_Bopen")
        self.horizontalLayout_2.addWidget(self.k_Bopen)
        self.k_convert = QtGui.QPushButton(k_widget)
        self.k_convert.setMaximumSize(QtCore.QSize(150, 30))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/kPrefix/icon/floatMask.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.k_convert.setIcon(icon)
        self.k_convert.setObjectName("k_convert")
        self.horizontalLayout_2.addWidget(self.k_convert)
        self.k_Bclose = QtGui.QPushButton(k_widget)
        self.k_Bclose.setMinimumSize(QtCore.QSize(0, 30))
        self.k_Bclose.setMaximumSize(QtCore.QSize(150, 30))
        self.k_Bclose.setDefault(False)
        self.k_Bclose.setObjectName("k_Bclose")
        self.horizontalLayout_2.addWidget(self.k_Bclose)
        self.k_wlayout.addLayout(self.horizontalLayout_2)

        self.retranslateUi(k_widget)
        QtCore.QMetaObject.connectSlotsByName(k_widget)

    def retranslateUi(self, k_widget):
        k_widget.setWindowTitle(QtGui.QApplication.translate("k_widget", "Form", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("k_widget", "转换格式", None, QtGui.QApplication.UnicodeUTF8))
        self.comboBox_2.setItemText(0, QtGui.QApplication.translate("k_widget", "map", None, QtGui.QApplication.UnicodeUTF8))
        self.comboBox_2.setItemText(1, QtGui.QApplication.translate("k_widget", "jpg", None, QtGui.QApplication.UnicodeUTF8))
        self.comboBox_2.setItemText(2, QtGui.QApplication.translate("k_widget", "tif", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("k_widget", "输出路径", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_2.setText(QtGui.QApplication.translate("k_widget", "浏览", None, QtGui.QApplication.UnicodeUTF8))
        self.k_label1.setText(QtGui.QApplication.translate("k_widget", "Text QT", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton.setText(QtGui.QApplication.translate("k_widget", "close", None, QtGui.QApplication.UnicodeUTF8))
        self.k_button2.setText(QtGui.QApplication.translate("k_widget", "来搞笑的", None, QtGui.QApplication.UnicodeUTF8))
        self.k_tabWidget.horizontalHeaderItem(0).setText(QtGui.QApplication.translate("k_widget", "文件名", None, QtGui.QApplication.UnicodeUTF8))
        self.k_tabWidget.horizontalHeaderItem(1).setText(QtGui.QApplication.translate("k_widget", "路径", None, QtGui.QApplication.UnicodeUTF8))
        self.k_tabWidget.horizontalHeaderItem(2).setText(QtGui.QApplication.translate("k_widget", "大小", None, QtGui.QApplication.UnicodeUTF8))
        self.k_Bopen.setText(QtGui.QApplication.translate("k_widget", "打开", None, QtGui.QApplication.UnicodeUTF8))
        self.k_convert.setText(QtGui.QApplication.translate("k_widget", "转换", None, QtGui.QApplication.UnicodeUTF8))
        self.k_Bclose.setText(QtGui.QApplication.translate("k_widget", "关闭", None, QtGui.QApplication.UnicodeUTF8))

import krc_rc
