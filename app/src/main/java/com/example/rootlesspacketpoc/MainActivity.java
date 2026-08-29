package com.example.rootlesspacketpoc;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import rikka.shizuku.Shizuku;

@SuppressLint("SetTextI18n")
public class MainActivity extends AppCompatActivity {

    private static final int SHIZUKU_PERMISSION_REQUEST = 1;
    private static final int PACKET_SERVICE_VERSION = 1;

    private TextView statusText;
    private Button connectButton;
    private Button runButton;

    private IPacketService packetService;

    private final Shizuku.OnRequestPermissionResultListener permissionResultListener =
            (requestCode, grantResult) -> {
                if (requestCode != SHIZUKU_PERMISSION_REQUEST) {
                    return;
                }

                if (grantResult == PackageManager.PERMISSION_GRANTED) {
                    startUserService();
                } else {
                    statusText.setText("Shizuku permission denied.");
                }
            };

    private final ServiceConnection userServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            packetService = IPacketService.Stub.asInterface(binder);

            try {
                statusText.setText("UserService UID: " + packetService.getUid());
                connectButton.setEnabled(false);
                runButton.setEnabled(true);

            } catch (RemoteException e) {
                packetService = null;
                runButton.setEnabled(false);
                statusText.setText("getUid failed:\n" + e);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            packetService = null;

            connectButton.setEnabled(true);
            runButton.setEnabled(false);

            statusText.setText("UserService disconnected.");
        }
    };

    private final Shizuku.UserServiceArgs userServiceArgs =
            new Shizuku.UserServiceArgs(
                    new ComponentName(
                            "com.example.rootlesspacketpoc",
                            PacketService.class.getName()
                    )
            )
                    .daemon(false)
                    .processNameSuffix("packet_service")
                    .version(PACKET_SERVICE_VERSION);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.statusText);
        connectButton = findViewById(R.id.connectButton);
        runButton = findViewById(R.id.runButton);

        Shizuku.addRequestPermissionResultListener(permissionResultListener);

        connectButton.setOnClickListener(v -> checkShizukuAndStart());
        runButton.setOnClickListener(v -> runPoc());
    }

    private void checkShizukuAndStart() {
        if (!Shizuku.pingBinder()) {
            statusText.setText("Shizuku is not running.");
            return;
        }

        try {
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                startUserService();
            } else if (Shizuku.shouldShowRequestPermissionRationale()) {
                statusText.setText("Shizuku permission denied.");
            } else {
                Shizuku.requestPermission(SHIZUKU_PERMISSION_REQUEST);
            }
        } catch (Throwable e) {
            statusText.setText("Shizuku error:\n" + e);
        }
    }

    private void startUserService() {
        statusText.setText("Binding UserService...");
        connectButton.setEnabled(false);

        try {
            Shizuku.bindUserService(userServiceArgs, userServiceConnection);
        } catch (Throwable e) {
            connectButton.setEnabled(true);
            statusText.setText("bindUserService failed:\n" + e);
        }
    }

    private void runPoc() {
        if (packetService == null) {
            return;
        }

        statusText.setText("Running PoC...");
        runButton.setEnabled(false);

        new Thread(() -> {
            try {
                String result = packetService.runPoc();

                runOnUiThread(() -> {
                    statusText.setText(result);
                    runButton.setEnabled(packetService != null);
                });

            } catch (RemoteException e) {
                runOnUiThread(() -> {
                    statusText.setText("runPoc failed:\n" + e);
                    runButton.setEnabled(packetService != null);
                });
            }
        }, "RunPoC").start();
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permissionResultListener);
        super.onDestroy();
    }
}